"""A cluster qualification remains bound to its actual isolated guest owners."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release as release
import android_release_lab_context as context
import android_release_network as network
import android_release_qualify as qualify
import android_release_lab_runtime as runtime


class IsolatedCluster(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.identity = {'schema': 1, 'vm_uuid': '79db4460-2ee6-43a2-8f58-2fbb12c28185',
            'android_pod_uid': '488cee51-cd94-4a25-9f5d-1050214888c3', 'android_pod_ip': '10.244.77.21',
            'boundary_sha256': 'a' * 64}
        for directory in ('hub', 'hub-home', 'release', 'fleet'):
            (self.root / directory).mkdir(mode=0o700)
        release.write_json(self.root / 'context.json', self.identity)
        release.write_json(self.root / 'fleet/controller.json', {'state': str(self.root / 'fleet'),
            'chatEndpoint': str(self.root / 'hub-home/gcd.chat')})
        self.config = {'qualification_scope': 'cluster-isolated', 'cluster_lab': self.identity,
            'state': str(self.root / 'release'), 'hub_directory': str(self.root / 'hub'),
            'hub_home': str(self.root / 'hub-home'), 'fleet_config': str(self.root / 'fleet/controller.json'),
            'hub_unit': 'gchat-android-cluster.service', 'fleet_unit': 'gdrone-android-cluster.service',
            'targets': [{'id': 'android-x64', 'kind': 'android', 'channel': 'android-x64',
                         'abi': 'x86_64', 'serial': '10.244.77.21:5555'}]}
        patcher = patch.object(context, 'ROOT', self.root)
        patcher.start(); self.addCleanup(patcher.stop)

    def test_same_guest_mapping_is_accepted_and_production_paths_are_refused(self):
        self.assertEqual(qualify.isolated(self.config)[1], self.config['targets'][0])
        for key, value in [('state', '/production'), ('hub_home', '/production'),
                ('fleet_config', '/production/controller.json'), ('hub_unit', 'gchat-fleet-host.service'),
                ('fleet_unit', 'gdrone-fleet.service')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                qualify.isolated(dict(self.config, **{key: value}))

    def test_replaced_guest_or_changed_boundary_cannot_reuse_the_mapping(self):
        for key, value in [('vm_uuid', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
                ('android_pod_uid', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
                ('boundary_sha256', 'b' * 64), ('android_pod_ip', '10.244.77.22')]:
            changed = dict(self.identity, **{key: value})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'identity or network boundary'):
                qualify.isolated(dict(self.config, cluster_lab=changed))
        changed = copy.deepcopy(self.config)
        changed['targets'][0]['serial'] = 'emulator-5554'
        with self.assertRaisesRegex(ValueError, 'pinned Android guest'):
            qualify.isolated(changed)

    def test_public_or_linked_context_cannot_authorize_guest_mutations(self):
        path = self.root / 'context.json'
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private owner file'):
            qualify.isolated(self.config)
        path.chmod(0o600); path.rename(self.root / 'retained.json'); path.symlink_to('retained.json')
        with self.assertRaises(OSError): qualify.isolated(self.config)

    def test_adb_reconnect_requires_the_same_pinned_guest_and_live_device(self):
        config = dict(self.config, adb='/private/adb')
        with patch.object(runtime.host, 'output', side_effect=[b'connected', b'device\n']) as output:
            runtime.connect_android(config)
            self.assertEqual(output.call_args_list[0].args[0],
                             ['/private/adb', 'connect', '10.244.77.21:5555'])
        with patch.object(runtime.host, 'output', side_effect=[b'connected', b'offline\n']):
            with self.assertRaisesRegex(ValueError, 'offline'): runtime.connect_android(config)
        changed = dict(config, cluster_lab=dict(self.identity, android_pod_ip='10.244.77.22'))
        with patch.object(runtime.host, 'output') as output:
            with self.assertRaises(ValueError): runtime.connect_android(changed)
            output.assert_not_called()

    def test_cluster_reference_does_not_claim_a_vpn_or_qualify_another_guest(self):
        proof = {'schema': 1, 'kind': 'android-runtime-qualification', 'inputs': {'sdk': 'c' * 64},
            'observed_at': 100, 'scope': 'cluster-isolated', 'cluster_lab': self.identity,
            'android': {key: True for key in ('full_download_verified', 'loaded_worker_ready',
                                            'identity_preserved', 'resume_verified')},
            'reference_transfer': {'bytes': 42 * 1024 * 1024, 'elapsed_seconds': 350,
                                  'sha256_verified': True, 'current_process_verified': True}}
        self.assertEqual(network.reference(proof, proof['inputs'], now=101, cluster_context=self.identity), proof)
        with self.assertRaises(ValueError): network.reference(proof, proof['inputs'], now=101)
        for changed in [dict(proof, vpn={'state': 'connected'}),
                dict(proof, scope='isolated emulator-5554'),
                dict(proof, cluster_lab=dict(self.identity, boundary_sha256='d' * 64)),
                dict(proof, reference_transfer=dict(proof['reference_transfer'], elapsed_seconds=361))]:
            with self.assertRaises(ValueError):
                network.reference(changed, proof['inputs'], now=101, cluster_context=self.identity)


if __name__ == '__main__': unittest.main()
