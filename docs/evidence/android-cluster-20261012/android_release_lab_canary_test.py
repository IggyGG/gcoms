"""Focused ownership and replay controls for the isolated failure fixture."""
import copy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, '/source/scripts')
import android_release as release
import android_release_lab_canary as canary
import android_release_lab_test as existing
import android_release_lab_runtime as runtime


class CanaryOwnership(unittest.TestCase):
    def setUp(self):
        existing.GuestExecution.setUp(self)
        patcher = patch.object(canary, 'ROOT', self.root)
        patcher.start(); self.addCleanup(patcher.stop)
        self.config['failure_canary'] = canary.KIND
        self.envelope['operation'] = 'readiness'
        prepared = self.envelope['prepared']
        prepared['configuration_sha256'] = hashlib.sha256(release.canonical(self.config)).hexdigest()
        prepared.pop('prepared_id')
        prepared['prepared_id'] = hashlib.sha256(release.canonical(prepared)).hexdigest()
        manifest = self.envelope['request']['manifest']
        manifest.update(configuration_sha256=prepared['configuration_sha256'], prepared_id=prepared['prepared_id'])
        manifest.pop('release_id')
        manifest['release_id'] = hashlib.sha256(release.canonical(manifest)).hexdigest()
        self.envelope['verification']['prepared_id'] = prepared['prepared_id']
        request, _ = runtime.validate(self.envelope)
        self.directory = Path(request['directory'])
        self.path = self.root / 'envelope.json'
        release.write_json(self.path, self.envelope)
        self.checksum = hashlib.sha256(release.canonical(self.envelope)).hexdigest()
        release.write_json(self.directory / 'activate-result.json', {'result': {'state': 'complete'},
            'envelope_sha256': hashlib.sha256(release.canonical(dict(self.envelope, operation='activate'))).hexdigest()})
        def artifact(_request, component, _name):
            return self.root / 'release/artifacts' / component / prepared['inputs'][component] / 'artifact'
        self.expected = {'release_id': manifest['release_id'],
                         'apk_sha256': release.digest(artifact(None, 'apk', None)),
                         'worker_sha256': release.digest(artifact(None, 'worker', None))}
        release.write_json(self.directory / 'android-x64/deployment-request.json', self.expected)
        release.write_json(self.directory / 'android-before.json',
                           [{'target': self.config['targets'][0], 'identity_sha256': 'original-seed'}])
        self.device_nonce = dict(self.expected)
        self.device_identity = 'original-seed'
        self.device_apk = self.expected['apk_sha256']
        self.pids = ['123', '123']
        def output(argv, **_kwargs):
            if 'pidof' in argv: return self.pids.pop(0).encode()
            if 'pm' in argv: return b'package:/data/app/owned/base.apk\n'
            if 'sha256sum' in argv: return (self.device_apk + ' /data/app/owned/base.apk\n').encode()
            raise AssertionError(argv)
        for name, kwargs in [
                ('artifact', {'side_effect': artifact}),
                ('private_file', {'side_effect': lambda *_a: json.dumps(self.device_nonce).encode()}),
                ('identity', {'side_effect': lambda *_a: self.device_identity}),
                ('output', {'side_effect': output})]:
            patcher = patch.object(canary.host, name, **kwargs)
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = patch.object(canary.host, 'command')
        self.stop = patcher.start(); self.addCleanup(patcher.stop)
        patcher = patch.object(canary.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b''))
        self.process_check = patcher.start(); self.addCleanup(patcher.stop)

    def run_fault(self):
        return canary.guest(str(self.path), self.checksum)

    def test_exact_fault_is_journaled_and_never_replayed(self):
        original = self.run_fault()
        self.assertEqual(original['state'], 'fault_observed')
        self.assertFalse(original['process_present'])
        self.assertEqual(original['prior_process_id'], 123)
        self.assertEqual(self.run_fault(), original)
        self.stop.assert_called_once()
        marker = self.directory / 'failed-canary-observation.json'
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        marker.unlink()
        with self.assertRaisesRegex(ValueError, 'uncertain'):
            self.run_fault()
        self.stop.assert_called_once()

    def test_changed_application_nonce_is_preserved(self):
        self.device_nonce['release_id'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'outside the exact canary release'):
            self.run_fault()
        self.stop.assert_not_called()

    def test_changed_identity_or_apk_or_process_is_preserved(self):
        self.device_identity = 'other-seed'
        with self.assertRaisesRegex(ValueError, 'changed Android identity'):
            self.run_fault()
        self.device_identity = 'original-seed'
        self.device_apk = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'changed canary APK'):
            self.run_fault()
        self.device_apk = self.expected['apk_sha256']
        self.pids = ['123', '456']
        with self.assertRaisesRegex(ValueError, 'process ownership'):
            self.run_fault()
        self.stop.assert_not_called()

    def test_uncertain_process_absence_does_not_repeat_the_fault(self):
        self.process_check.return_value = SimpleNamespace(returncode=0, stdout=b'999\n')
        with self.assertRaisesRegex(ValueError, 'process absent'):
            self.run_fault()
        with self.assertRaisesRegex(ValueError, 'uncertain'):
            self.run_fault()
        self.stop.assert_called_once()

    def test_changed_envelope_or_incomplete_activation_refuses_mutation(self):
        with self.assertRaisesRegex(ValueError, 'envelope changed'):
            canary.guest(str(self.path), 'f' * 64)
        release.write_json(self.directory / 'activate-result.json', {'result': {'state': 'complete'},
                           'envelope_sha256': 'f' * 64})
        with self.assertRaisesRegex(ValueError, 'completed real activation'):
            self.run_fault()
        self.stop.assert_not_called()

    def test_production_or_implicit_scope_is_never_accepted(self):
        for changed in [dict(self.config, qualification_scope='production'),
                        {k: v for k, v in self.config.items() if k != 'failure_canary'}]:
            with self.assertRaisesRegex(ValueError, 'explicit prepared isolated-lab'):
                canary.required(changed)
        self.stop.assert_not_called()


if __name__ == '__main__':
    unittest.main()
