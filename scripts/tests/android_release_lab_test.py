"""Cluster staging and guest mutation preserve exact original execution ownership."""
import copy
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release as release
import android_release_lab as adapter
import android_release_lab_runtime as runtime
import android_release_lab_context_test as context_tests
import android_release_cluster as cluster


class GuestExecution(unittest.TestCase):
    def setUp(self):
        context_tests.IsolatedCluster.setUp(self)
        patcher = patch.object(runtime, 'ROOT', self.root)
        patcher.start(); self.addCleanup(patcher.stop)
        connection = patch.object(runtime, 'connect_android')
        self.connection = connection.start(); self.addCleanup(connection.stop)
        self.config.update(baseline_receipt=str(self.root / 'baseline.json'))
        inputs, receipts = {}, {}
        for component in release.COMPONENTS:
            key = hashlib.sha256(component.encode()).hexdigest(); inputs[component] = key
            folder = self.root / 'release/artifacts' / component / key
            folder.mkdir(parents=True)
            data = (component + '-prepared').encode(); (folder / 'artifact').write_bytes(data)
            receipt = {'component': component, 'input_sha256': key,
                       'files': {'artifact': hashlib.sha256(data).hexdigest()}}
            release.write_json(folder / 'receipt.json', receipt)
            receipts[component] = hashlib.sha256(release.canonical(receipt)).hexdigest()
        prepared = {'schema': 1, 'kind': 'android-prepared-release', 'sources': {'gcoms': 'a' * 40},
            'inputs': inputs, 'targets': self.config['targets'], 'artifacts': receipts,
            'configuration_sha256': hashlib.sha256(release.canonical(self.config)).hexdigest()}
        prepared['prepared_id'] = hashlib.sha256(release.canonical(prepared)).hexdigest()
        manifest = {k: prepared[k] for k in ('sources', 'inputs', 'targets', 'configuration_sha256')}
        manifest.update(schema=1, prepared_id=prepared['prepared_id'], pushed_at=100)
        manifest['release_id'] = hashlib.sha256(release.canonical(manifest)).hexdigest()
        self.envelope = {'schema': 1, 'operation': 'activate', 'prepared': prepared,
            'request': {'config': self.config, 'manifest': manifest, 'directory': '/cluster/original', 'warm': False},
            'verification': {'schema': 1, 'prepared_id': prepared['prepared_id'], 'artifacts': receipts,
                             'apk_signature_verified': True}}

    def test_changed_prepared_input_or_staged_bytes_are_refused_before_mutation(self):
        runtime.validate(self.envelope)
        changed = copy.deepcopy(self.envelope); changed['prepared']['inputs']['sdk'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'prepared source/configuration'):
            runtime.validate(changed)
        changed = copy.deepcopy(self.envelope); changed['verification']['apk_signature_verified'] = False
        with self.assertRaisesRegex(ValueError, 'APK verification'):
            runtime.validate(changed)
        path = self.root / 'release/artifacts/sdk' / self.envelope['prepared']['inputs']['sdk'] / 'artifact'
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            runtime.validate(self.envelope)

    def test_interrupted_guest_activation_is_never_replayed_as_a_fresh_attempt(self):
        with patch.object(runtime.host, 'activate', side_effect=OSError('interrupted')) as activate:
            failed = runtime.execute(self.envelope)
            self.assertEqual(failed['result'], {'state': 'failed', 'failure_type': 'OSError'})
            self.assertEqual(runtime.execute(self.envelope), failed)
            self.assertEqual(activate.call_count, 1)
            self.assertEqual(self.connection.call_count, 1)
        marker = self.root / 'release/runs' / self.envelope['request']['manifest']['release_id'] / 'activate-result.json'
        marker.unlink()  # Process loss after journaling, before the result commit.
        with self.assertRaisesRegex(ValueError, 'uncertain outcome'): runtime.execute(self.envelope)
        restored = dict(self.envelope, operation='rollback')
        with patch.object(runtime.host, 'rollback') as rollback:
            result = runtime.execute(restored)
            self.assertEqual(result['result']['state'], 'complete')
            rollback.assert_called_once()

    def test_completed_guest_result_keeps_its_original_completion_and_binding(self):
        with patch.object(runtime.host, 'activate') as activate:
            first = runtime.execute(self.envelope)
            self.assertEqual(runtime.execute(self.envelope), first)
            activate.assert_called_once()
        changed = copy.deepcopy(self.envelope)
        changed['request']['directory'] = '/cluster/changed'
        with self.assertRaisesRegex(ValueError, 'original guest execution binding'):
            runtime.execute(changed)


class GuestStaging(unittest.TestCase):
    def test_receiver_refuses_traversal_links_and_replacement_of_immutable_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receiver = adapter.RECEIVER.replace(str(adapter.ROOT), str(root))
            def send(name, data=b'original', link=None):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w') as archive:
                    member = tarfile.TarInfo(name); member.size = len(data); member.mode = 0o600
                    if link:
                        member.type = tarfile.SYMTYPE; member.linkname = link; member.size = 0
                        archive.addfile(member)
                    else: archive.addfile(member, io.BytesIO(data))
                return subprocess.run([sys.executable, '-c', receiver], input=buffer.getvalue(),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(send('commands/original.json').returncode, 0)
            self.assertEqual(send('commands/original.json').returncode, 0)
            for name, data, link in [('commands/original.json', b'changed', None),
                    ('../outside', b'bad', None), ('commands/link', b'', '/tmp/outside'),
                    ('foreign/path', b'bad', None)]:
                self.assertNotEqual(send(name, data, link).returncode, 0)
            self.assertEqual((root / 'commands/original.json').read_bytes(), b'original')
            self.assertFalse((root / 'commands/link').exists())
            self.assertEqual(list(root.rglob('.stage-*')), [])


class QualificationIdentity(unittest.TestCase):
    def test_repeated_observation_keeps_original_manifest_and_directory(self):
        config = {'state': '/cluster', 'cluster_lab': {}}
        manifest = {'prepared_id': 'a' * 64, 'pushed_at': 100, 'release_id': 'b' * 64}
        with patch.object(adapter, 'prepared_release', return_value={}), \
             patch.object(adapter, 'promotion_manifest', return_value=manifest) as bind, \
             patch.object(adapter, 'remote', return_value={'state': 'failed'}) as remote, \
             patch.object(adapter.time, 'time', return_value=900):
            adapter.qualify(config, manifest)
            adapter.qualify(config, manifest)
        self.assertEqual(remote.call_args_list[0], remote.call_args_list[1])
        self.assertEqual(remote.call_args.args[0]['manifest']['pushed_at'], 100)
        bind.assert_called_with(config, 'a' * 64, 100)


class LabReservation(unittest.TestCase):
    def setUp(self):
        self.config = {'qualification_scope': 'cluster-isolated', 'lab': {
            'settings': '/config/lab.json', 'network_guest': 'network', 'android_pod': 'gl-android',
            'reservation_id': '51e38b01-6edc-4b62-8cd8-b36cdb2f36a2'}}
        self.active = []
        self.checked = []
        @contextmanager
        def reserve(name, owner):
            self.assertEqual(owner, self.config['lab']['reservation_id'])
            self.active.append(name)
            def fence():
                self.assertIn(name, self.active)
                self.checked.append(name)
            try: yield fence
            finally: self.active.remove(name)
        self.lab = SimpleNamespace(kube=SimpleNamespace(reservation=reserve))
        patcher = patch.object(adapter, 'create_lab', return_value=self.lab)
        self.create = patcher.start(); self.addCleanup(patcher.stop)

    def test_both_reservations_cover_the_entire_remote_operation(self):
        request = {'config': self.config, 'manifest': {'prepared_id': 'a' * 64}}
        def execute(original, operation, prepared, lab, fence):
            self.assertIs(original, request)
            self.assertEqual(self.active, ['android', 'network'])
            self.assertIs(lab, self.lab)
            fence()
            return {'state': 'complete'}
        with patch.object(adapter, 'remote_reserved', side_effect=execute):
            result = adapter.remote(request, 'activate', {'prepared_id': 'a' * 64})
        self.assertEqual(result['state'], 'complete')
        self.assertEqual(self.active, [])
        self.assertEqual(set(self.checked), {'android', 'network'})

    def test_supervisor_holds_lab_across_idle_ticks_and_stops_when_fenced(self):
        class End(Exception): pass
        def tick(config):
            self.assertEqual(self.active, ['android', 'network'])
            return {'state': 'idle'}
        with patch.object(cluster, 'tick', side_effect=tick) as observe, \
             patch.object(cluster.time, 'sleep', side_effect=End):
            with self.assertRaises(End): cluster.serve(self.config)
            observe.assert_called_once()
        self.assertEqual(self.active, [])
        with patch.object(cluster, 'tick') as observe:
            with self.assertRaisesRegex(ValueError, 'lost'):
                cluster.supervise(self.config, Mock(side_effect=ValueError('lost')))
            observe.assert_not_called()

    def test_invalid_or_unreserved_configuration_cannot_contact_the_guest(self):
        for key, value in [('android_pod', 'outside'), ('android_pod', 'gl-network'),
                           ('network_guest', '../network'), ('network_guest', {})]:
            config = copy.deepcopy(self.config); config['lab'][key] = value
            with self.assertRaises(ValueError):
                with adapter.reserved_lab(config): pass
        self.create.assert_not_called()
        config = copy.deepcopy(self.config); del config['lab']['reservation_id']
        with self.assertRaises(KeyError):
            with adapter.reserved_lab(config): pass
        self.create.assert_not_called()

    def test_discarded_or_missing_guest_has_explicit_failure_before_staging(self):
        config = dict(self.config, cluster_lab={'unused': True})
        expected = {'vm_uuid': 'original', 'boundary_sha256': 'boundary'}
        lab = Mock(); lab.settings.namespace = 'ghost-lab'
        state = {'machine_uuid': 'original', 'phase': 'discarded', 'resource': 'gl-network'}
        lab.state.return_value = state
        qualification = SimpleNamespace(require=Mock(return_value={'network_sha256': 'boundary'}))
        with patch.dict(sys.modules, {'ghost_lab.qualification': qualification}), \
             patch.object(adapter, 'identity', return_value=expected):
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                adapter.qualified_lab(config, lab)
            lab.kube.get.assert_not_called()
            state['phase'] = 'booting'; lab.kube.get.return_value = None
            with self.assertRaisesRegex(ValueError, 'not ready'):
                adapter.qualified_lab(config, lab)


if __name__ == '__main__': unittest.main()
