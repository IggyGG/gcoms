"""Compiler cache ownership and private credential scope of native Jobs."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

# These exercise the POSIX deployment coordinator, not the native Android SDK.
if sys.platform == 'win32':
    raise unittest.SkipTest('POSIX Android deployment orchestration')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release as release
import android_release_build_job as build
from android_release_kubernetes_test import API


class NativeJobs(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.api = API()
        self.config = {'state': str(self.root), 'kubernetes': {'namespace': 'ghost'},
            'cluster': {'builder_image': 'registry.example/android@sha256:' + 'a' * 64,
                        'state_claim': 'android-state', 'cache_claims': {c: 'android-cache-' + c for c in release.COMPONENTS},
                        'signing_secret': 'android-apk-signing'}}
        self.request = {'config': self.config, 'component': 'sdk', 'output': str(self.root / 'artifact'),
                        'manifest': {'release_id': 'b' * 64, 'inputs': {'sdk': 'c' * 64}}}
        self.path = self.root / 'sdk-request.json'
        release.write_json(self.path, self.request)

    def completed_api(self):
        create = self.api.create
        def complete(kind, value):
            result = create(kind, value)
            if kind == 'job':
                result['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}]}
                self.api.objects[kind, value['metadata']['name']] = copy.deepcopy(result)
            return result
        return patch.object(self.api, 'create', side_effect=complete)

    def test_native_jobs_have_no_api_or_archive_token_and_only_apk_gets_signing(self):
        for component in release.COMPONENTS:
            self.request['component'] = component
            value = build.native_job(self.request, self.path)
            pod = value['spec']['template']['spec']
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertEqual(value['spec']['backoffLimit'], 0)
            self.assertEqual(value['spec']['activeDeadlineSeconds'], 3300)
            self.assertEqual(pod['containers'][0]['resources']['limits']['cpu'], '2')
            secrets = [v['secret']['secretName'] for v in pod['volumes'] if 'secret' in v]
            self.assertEqual(secrets, ['android-apk-signing'] if component == 'apk' else [])
            self.assertEqual(next(v for v in pod['volumes'] if v['name'] == 'cache')['persistentVolumeClaim']['claimName'],
                             'android-cache-' + component)

    def test_native_builder_image_and_component_are_explicit(self):
        self.request['component'] = 'unrelated-platform'
        with self.assertRaises(ValueError):build.native_job(self.request, self.path)
        self.request['component'] = 'sdk';self.config['cluster']['builder_image'] = 'image:latest'
        with self.assertRaisesRegex(ValueError, 'digest-pinned'):build.native_job(self.request, self.path)

    def test_runtime_overlay_keeps_compiler_pin_and_refuses_changed_execution_code(self):
        image = self.config['cluster']['builder_image']
        self.config['cluster']['runtime_config_map'] = 'android-runtime-source-pinned'
        pod = build.native_job(self.request, self.path)['spec']['template']['spec']
        self.assertEqual(pod['containers'][0]['image'], image)
        self.assertIn({'name': 'runtime', 'mountPath': '/opt/gcoms/scripts', 'readOnly': True},
                      pod['containers'][0]['volumeMounts'])
        runtime = self.root / 'runtime.py'; runtime.write_text('original')
        self.config['runtime_sha256'] = {str(runtime): release.digest(runtime)}
        release.write_json(self.path, self.request)
        runtime.write_text('changed after the immutable request was prepared')
        with patch.object(build, 'inputs') as inputs, self.assertRaisesRegex(ValueError, 'execution code changed'):
            build.execute(self.path, hashlib.sha256(release.canonical(self.request)).hexdigest())
        inputs.assert_not_called()

    def test_cache_writer_intent_is_durable_before_job_admission(self):
        create = self.api.create
        def observed(kind, value):
            if kind == 'job':
                owner = json.loads(self.api.get('configmap', 'android-build-sdk')['data']['owner.json'])
                self.assertEqual(owner['name'], value['metadata']['name'])
                self.assertIsNone(owner['uid'])
            result = create(kind, value)
            if kind == 'job':
                result['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}]}
                self.api.objects[kind, value['metadata']['name']] = result
            return result
        with patch.object(self.api, 'create', side_effect=observed), patch.object(build, 'cached_artifact', return_value={'verified': True}):
            build.remote(self.path, self.api)
        owner = json.loads(self.api.get('configmap', 'android-build-sdk')['data']['owner.json'])
        self.assertTrue(owner['uid'])

    def test_original_completed_job_is_reconciled_without_another_cache_writer(self):
        with self.completed_api(), patch.object(build, 'cached_artifact', return_value={'verified': True}):
            build.remote(self.path, self.api)
            uid = json.loads(self.path.with_suffix('.job.json').read_text())['uid']
            build.remote(self.path, self.api)
        self.assertEqual(len([k for k in self.api.objects if k[0] == 'job']), 1)
        self.assertEqual(json.loads(self.path.with_suffix('.job.json').read_text())['uid'], uid)

    def test_lost_admission_reply_without_local_marker_still_adopts_exact_writer(self):
        create = self.api.create
        def lost(kind, value):
            result = create(kind, value)
            if kind == 'job':
                result['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}]}
                self.api.objects[kind, value['metadata']['name']] = result
                raise TimeoutError('lost admission reply')
            return result
        with patch.object(self.api, 'create', side_effect=lost), self.assertRaises(TimeoutError):
            build.remote(self.path, self.api)
        self.path.with_suffix('.job.json').unlink()
        with patch.object(build, 'cached_artifact', return_value={'verified': True}):
            build.remote(self.path, self.api)
        self.assertEqual(len([k for k in self.api.objects if k[0] == 'job']), 1)

    def test_missing_cache_writer_blocks_a_new_source_even_after_working_cache_loss(self):
        create = self.api.create
        def absent(kind, value):
            if kind == 'job':raise TimeoutError('unknown admission')
            return create(kind, value)
        with patch.object(self.api, 'create', side_effect=absent), self.assertRaises(TimeoutError):
            build.remote(self.path, self.api)
        self.path.with_suffix('.job.json').unlink()
        self.request['manifest']['release_id'] = 'd' * 64
        release.write_json(self.path, self.request)
        with self.assertRaisesRegex(ValueError, 'cache writer is missing'):
            build.remote(self.path, self.api)
        self.assertFalse(any(k[0] == 'job' for k in self.api.objects))

    def test_completed_build_without_artifact_receipt_is_not_success(self):
        with self.completed_api(), patch.object(build, 'cached_artifact', return_value=None):
            with self.assertRaisesRegex(ValueError, 'omitted its artifact'):
                build.remote(self.path, self.api)

    def test_changed_execution_request_is_rejected_before_compilation(self):
        with self.assertRaisesRegex(ValueError, 'binding changed'):
            build.execute(self.path, '0' * 64)


if __name__ == '__main__':
    unittest.main()
