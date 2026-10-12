import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release_lab_provision as provision
import android_release_store as store
from android_release_store_test import S3


class Provisioning(unittest.TestCase):
    def setUp(self):
        self.plan = {'schema': 1, 'owner': 'fe38fb6c-f2b6-4c28-9c91-b101dd480e3f',
            'guests': {'android': {'name': 'pipeline-android', 'image': 'android'},
                       'network': {'name': 'pipeline-network', 'image': 'linux'}},
            'service': 'pipeline-network', 'preserved_instances': ['discarded-old']}

    def test_plan_refuses_duplicate_and_preserved_names_before_operations(self):
        provision.validate(self.plan)
        for key, value in [('name', 'discarded-old'), ('name', 'pipeline-network'), ('name', '../injected')]:
            plan = copy.deepcopy(self.plan); plan['guests']['android'][key] = value
            with self.assertRaises(ValueError): provision.validate(plan)
        plan = dict(self.plan, owner='00000000-0000-0000-0000-000000000000')
        with self.assertRaises(ValueError): provision.validate(plan)

    def test_existing_service_cannot_change_owner_selector_or_expose_guests(self):
        lab = Mock(); lab.settings.namespace = 'ghost-lab'
        current = {'metadata': {'labels': {'ghost.io/pipeline': self.plan['owner']}},
            'spec': {'type': 'ClusterIP', 'selector': {'ghost.io/instance': 'gl-pipeline-network'},
                     'ports': [dict(p, protocol=p.get('protocol', 'TCP')) for p in provision.PORTS], 'clusterIP': '10.100.1.2'}}
        lab.kube.get.return_value = current
        self.assertEqual(provision.service(lab, self.plan), '10.100.1.2')
        changes = [lambda x: x['metadata']['labels'].update({'ghost.io/pipeline': 'foreign'}),
                   lambda x: x['spec'].update(type='NodePort'),
                   lambda x: x['spec'].update(externalIPs=['203.0.113.1']),
                   lambda x: x['spec'].update(selector={'app': 'foreign'}),
                   lambda x: x['spec']['ports'].append({'port': 22, 'targetPort': 22, 'protocol': 'TCP'}),
                   lambda x: x['spec'].update(clusterIP='192.0.2.1')]
        for mutate in changes:
            value = copy.deepcopy(current); mutate(value); lab.kube.get.return_value = value
            with self.assertRaises(ValueError): provision.service(lab, self.plan)
        lab.kube.create.assert_not_called()
        lab.kube.apply.assert_not_called()

    def test_bootstrap_cannot_repeat_a_failed_or_uncertain_guest_action(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); evidence = root / 'evidence'
            script = root / 'bootstrap.py'
            script.write_text("from pathlib import Path\np=Path(__file__).with_name('count');p.write_text(p.read_text()+'x' if p.exists() else 'x')\nraise ValueError('private failure')\n")
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, 'original guest bootstrap failed'):
                    provision.execute_once(['/bin/sh', '-c'], root, script.name, 'original', evidence)
            self.assertEqual((root / 'count').read_text(), 'x')
            result = root / 'bootstrap.py.result.json'; result.unlink()
            with self.assertRaisesRegex(ValueError, 'uncertain'):
                provision.execute_once(['/bin/sh', '-c'], root, script.name, 'original', evidence)
            self.assertEqual((root / 'count').read_text(), 'x')

    def test_completed_bootstrap_recovers_original_proof_and_refuses_changed_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); script = root / 'bootstrap.py'; evidence = root / 'evidence'
            script.write_text("from pathlib import Path\np=Path(__file__).with_name('count');p.write_text(p.read_text()+'x' if p.exists() else 'x')\nprint('{\"state\":\"ready\"}')\n")
            first = provision.execute_once(['/bin/sh', '-c'], root, script.name, 'original', evidence)
            self.assertEqual(provision.execute_once(['/bin/sh', '-c'], root, script.name, 'original', evidence), first)
            self.assertEqual(first, {'state': 'ready'})
            with self.assertRaisesRegex(ValueError, 'uncertain'):
                provision.execute_once(['/bin/sh', '-c'], root, script.name, 'changed', evidence)
            self.assertEqual((root / 'count').read_text(), 'x')

    def access_fixture(self, root):
        state = {'name': 'pipeline-network', 'reservation_owner': self.plan['owner'],
                 'machine_uuid': '4eb258ef-7048-4a1a-83bb-402bcfe447da'}
        directory = root / 'operator' / state['name']; directory.mkdir(parents=True, mode=0o700)
        key = directory / 'id_ed25519'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        (directory / 'known_hosts').write_bytes(state['machine_uuid'].encode() + b' ' + (directory / 'id_ed25519.pub').read_bytes())
        lab = SimpleNamespace(settings=SimpleNamespace(state_dir=str(directory.parent)))
        settings = {'state': str(root / 'pipeline'), 'archive': {}}
        archive = store.Archive({'endpoint': store.ENDPOINT, 'region': 'fsn1',
            'bucket': 'private-android-artifacts'}, S3())
        return state, directory, lab, settings, archive

    def test_access_restores_original_keys_into_empty_cache_and_preserves_existing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); state, original, lab, settings, archive = self.access_fixture(root)
            expected = {name: (original / name).read_bytes() for name in provision.ACCESS_FILES}
            with patch.object(provision, 'Archive', return_value=archive):
                result = provision.archive_access(lab, self.plan, settings, state)
                settings['access_archive'] = result['archive']
                lab.settings.state_dir = str(root / 'empty')
                provision.restore_access(lab, self.plan, settings, state)
                restored = Path(lab.settings.state_dir) / state['name']
                self.assertEqual({name: (restored / name).read_bytes() for name in provision.ACCESS_FILES}, expected)
                self.assertTrue(all((restored / name).stat().st_mode & 0o777 == 0o600 for name in provision.ACCESS_FILES))
                with self.assertRaisesRegex(ValueError, 'preserve'):
                    provision.restore_access(lab, self.plan, settings, state)
                lab.settings.state_dir = str(root / 'foreign')
                with self.assertRaisesRegex(ValueError, 'binding differs'):
                    provision.restore_access(lab, self.plan, settings, dict(state, machine_uuid=self.plan['owner']))
                self.assertFalse(Path(lab.settings.state_dir).exists())

    def test_access_refuses_symlink_exposed_key_and_wrong_vm_host_key_before_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); state, directory, lab, settings, archive = self.access_fixture(root)
            key = directory / 'id_ed25519'
            key.chmod(0o644)
            with patch.object(provision, 'Archive') as factory:
                with self.assertRaises(ValueError): provision.archive_access(lab, self.plan, settings, state)
                factory.assert_not_called()
            key.chmod(0o600)
            with self.assertRaises(ValueError): provision.verify_access(directory, dict(state, machine_uuid=self.plan['owner']))
            saved = directory / 'saved'; key.rename(saved); key.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, 'symlinks'): provision.verify_access(directory, state)

    def test_access_refuses_extra_files_or_public_modes_before_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); state, original, lab, settings, archive = self.access_fixture(root)
            with patch.object(provision, 'Archive', return_value=archive):
                result = provision.archive_access(lab, self.plan, settings, state)
                lab.settings.state_dir = str(root / 'empty')
                original_record = archive.read_record(result['archive'])
                for extra in (False, True):
                    changed = copy.deepcopy(original_record)
                    if extra: changed['files']['unrelated-token'] = changed['files']['id_ed25519']
                    else: changed['files']['id_ed25519']['mode'] = 0o644
                    settings['access_archive'] = archive.publish_record(changed)
                    with self.assertRaisesRegex(ValueError, 'inventory'):
                        provision.restore_access(lab, self.plan, settings, state)
                    self.assertFalse(Path(lab.settings.state_dir).exists())

    def test_failed_attempts_survive_pod_log_loss_and_archive_outage_without_public_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = root / 'settings.json'
            config.write_text(json.dumps({'state': str(root / 'state'), 'archive': {}}))
            out = io.StringIO()
            with patch.object(provision, 'provision', side_effect=ValueError('private-sentinel')), \
                    patch.object(provision, 'Archive', side_effect=OSError('private-archive-sentinel')), redirect_stdout(out):
                for _ in range(2):
                    with self.assertRaises(SystemExit) as failed:
                        provision.main(['--config', str(config), 'android'])
                    self.assertEqual(failed.exception.code, 1)
            attempts = list((root / 'state/attempts').iterdir())
            self.assertEqual(len(attempts), 2)
            self.assertNotIn('sentinel', out.getvalue())
            for directory in attempts:
                self.assertIn('private-sentinel', (directory / 'failure-private.json').read_text())
                self.assertEqual((directory / 'failure-private.json').stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads((directory / 'result.json').read_text())['result']['state'], 'failed')


if __name__ == '__main__': unittest.main()
