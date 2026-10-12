import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release_lab_provision as provision


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


if __name__ == '__main__': unittest.main()
