"""The cluster request survives workstation loss and uncertain Job submission."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if sys.platform == 'win32':
    raise unittest.SkipTest('POSIX Android deployment orchestration')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release as release
import android_release_cluster as cluster
from android_release_catalogue import Catalogue
from android_release_kubernetes import Lease
from android_release_kubernetes_test import API
from android_release_store import Archive, ENDPOINT
from android_release_store_test import S3


class ClusterRecovery(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'state'
        self.config = {'state': str(self.root), 'event_directory': str(self.root / 'events'),
            'kubernetes': {'namespace': 'ghost'},
            'forgejo': {'url': 'https://forgejo.example', 'token_file': '/credentials/forgejo/token'},
            'archive': {'endpoint': ENDPOINT, 'region': 'fsn1', 'bucket': 'android-fixture',
                        'catalogue': 'android-release-objects'},
            'sources': {'gcoms': {'project': 'gcoms', 'cluster_repository': 'ghost-local/gcoms',
                        'ref': 'refs/heads/main', 'repository': str(self.root / 'sources/gcoms.git')}},
            'cluster': {'runner_image': 'registry.example/runner@sha256:' + 'd' * 64,
                        'state_claim': 'android-state', 'config_map': 'android-config',
                        'archive_secret': 'android-archive', 'service_account': 'android-release'}}
        self.api = API()
        self.archive = Archive(self.config['archive'], S3())
        self.catalogue = Catalogue(self.config, self.api, self.archive)
        release.write_json(self.root / 'source-cursors.json', {'ghost-local/gcoms': 12})
        release.write_json(self.root / 'source-migration.json', {'cursors': {'ghost-local/gcoms': 10}})
        request = {'schema': 1, 'operation': 'prepare', 'manifest': {'pushed_at': 100,
                   'configuration_sha256': hashlib.sha256(release.canonical(self.config)).hexdigest()},
                   'events': ['gcoms-12.json'], 'source_push': {'pushed_at': 90, 'forgejo_activity_id': 12}}
        request['request_id'] = hashlib.sha256(release.canonical(request)).hexdigest()
        self.request = request
        self.marker = self.root / 'cluster-effects' / (request['request_id'] + '.json')

    def submit(self):
        with Lease(self.api, 'android-release-coordinator') as lease:
            return cluster.submit(self.config, self.api, lease, self.request, self.marker, self.catalogue)

    def test_first_source_sync_creates_private_logs_before_invoking_git(self):
        logs = []
        def executed(argv, **kwargs):
            # Exercise the real logging sink on an empty state volume. Git's
            # transport is replaced so the control uses no remote credentials.
            release.command([sys.executable, '-c', 'pass'], log=kwargs['log'])
            logs.append(kwargs['log'])
        with patch.object(cluster, 'command', side_effect=executed), \
             patch.object(cluster, 'advertised_refs', return_value={'refs/heads/main': 'a' * 40}), \
             patch.object(cluster, 'git', return_value=b'https://forgejo.example/ghost-local/gcoms.git\n'):
            cluster.source_sync(self.config)
        self.assertEqual(len(logs), 3)
        self.assertTrue(all(path.is_file() for path in logs))
        self.assertEqual((self.root / 'source-logs').stat().st_mode & 0o777, 0o700)

    def test_source_sync_fetches_both_selected_branches_without_unrelated_refs(self):
        origin = self.root / 'fixture-origin'
        origin.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '--shallow-file', '/dev/null', '-C', str(origin), *args],
                                           stderr=subprocess.DEVNULL)
        git('init', '-b', 'main')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '--allow-empty', '-m', 'fixture')
        git('branch', 'agent/android'); git('branch', 'unrelated')
        git('tag', 'unrelated-tag'); git('tag', 'android-release/' + 'a' * 64)
        self.config['sources']['agent'] = dict(self.config['sources']['gcoms'], ref='refs/heads/agent/android')
        original = cluster.command
        def transport(argv, **kwargs):
            argv = list(argv)
            if 'fetch' in argv or 'ls-remote' in argv:
                argv[argv.index('origin')] = str(origin)
            return original(argv, **kwargs)
        with patch.object(cluster, 'command', side_effect=transport):
            cluster.source_sync(self.config)
        mirror = self.config['sources']['gcoms']['repository']
        refs = release.git(mirror, 'for-each-ref', '--format=%(refname)').decode().splitlines()
        self.assertEqual(set(refs), {'refs/heads/main', 'refs/heads/agent/android'})
        def unchanged(argv, **kwargs):
            self.assertNotIn('fetch', argv)
            return transport(argv, **kwargs)
        with patch.object(cluster, 'command', side_effect=unchanged):
            cluster.source_sync(self.config)
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '--allow-empty', '-m', 'newer')
        git('tag', 'android-release/' + 'b' * 64)
        git('tag', 'android-release/' + 'c' * 64)
        # A prepared promotion names a commit already imported for preparation.
        with patch.object(cluster, 'command', side_effect=transport):
            cluster.source_sync(self.config)
        before = release.git(mirror, 'rev-parse', 'refs/heads/main')
        with patch.object(cluster, 'command', side_effect=unchanged):
            cluster.source_sync(self.config, promotion='refs/tags/android-release/' + 'b' * 64)
        refs = release.git(mirror, 'for-each-ref', '--format=%(refname)').decode().splitlines()
        self.assertEqual(set(refs), {'refs/heads/main', 'refs/heads/agent/android',
            'refs/tags/android-release/' + 'b' * 64})
        self.assertEqual(release.git(mirror, 'rev-parse', 'refs/heads/main'), before)

    def test_source_sync_rejects_wildcard_before_git(self):
        self.config['sources']['gcoms']['ref'] = 'refs/heads/*'
        with patch.object(cluster, 'command') as command, self.assertRaisesRegex(ValueError, 'exact branch'):
            cluster.source_sync(self.config)
        command.assert_not_called()

    def test_prepared_promotion_is_admitted_while_one_cold_preparation_runs(self):
        self.submit()
        tag = 'refs/tags/android-release/' + 'a' * 64
        event = {'project': 'gcoms', 'ref': tag, 'commit': 'b' * 40,
                 'pushed_at': 150, 'server_event_id': 'c' * 64}
        release.write_json(self.root / 'events/promotion.json', event)
        manifest = {'sources': {'gcoms': 'b' * 40}, 'pushed_at': 150,
                    'configuration_sha256': hashlib.sha256(release.canonical(self.config)).hexdigest()}
        with patch.object(cluster, 'ingest'), patch.object(cluster, 'source_sync') as sync, \
             patch.object(cluster, 'promotion_manifest', return_value=manifest):
            result = cluster.tick(self.config, self.api, self.catalogue)
        self.assertEqual({v['operation'] for v in result['active']}, {'prepare', 'promote'})
        sync.assert_called_once_with(self.config, promotion=tag)
        requests = [json.loads(p.read_text())['request'] for p in (self.root / 'cluster-effects').glob('*.json')]
        promotion = next(v for v in requests if v['operation'] == 'promote')
        self.assertEqual(promotion['source_push'], event)
        self.assertEqual(promotion['manifest']['pushed_at'], 150)
        with patch.object(cluster, 'ingest'), patch.object(cluster, 'source_sync') as sync:
            cluster.tick(self.config, self.api, self.catalogue)
        sync.assert_not_called()
        self.assertEqual(len(list((self.root / 'cluster-effects').glob('*.json'))), 2)

    def test_active_preparation_keeps_new_source_events_pending(self):
        self.submit()
        event = {'project': 'gcoms', 'ref': 'refs/heads/main', 'commit': 'b' * 40,
                 'pushed_at': 150, 'server_event_id': 'c' * 64}
        release.write_json(self.root / 'events/newer.json', event)
        with patch.object(cluster, 'ingest'), patch.object(cluster, 'source_sync') as sync:
            result = cluster.tick(self.config, self.api, self.catalogue)
        sync.assert_not_called()
        self.assertEqual(len(result['active']), 1)
        self.assertEqual(result['active'][0]['operation'], 'prepare')
        self.assertTrue((self.root / 'events/newer.json').is_file())

    def test_promotion_fetch_rejects_wildcards_and_branches_before_git(self):
        for ref in ('refs/tags/android-release/*', 'refs/heads/main'):
            with patch.object(cluster, 'command') as command, self.assertRaisesRegex(ValueError, 'exact immutable tag'):
                cluster.source_sync(self.config, promotion=ref)
            command.assert_not_called()

    def test_remote_checkpoint_precedes_job_submission_and_retains_original_clocks(self):
        create = self.api.create
        seen = []
        def observed(kind, value):
            if kind == 'job':
                pointer = self.catalogue.lookup('checkpoints', 'coordinator')
                checkpoint = self.archive.read_record(pointer)
                effect = checkpoint['files'][str(self.marker.relative_to(self.root))]
                self.assertTrue(effect['submission_started'])
                self.assertEqual(effect['request'], self.request)
                seen.append(True)
            return create(kind, value)
        with patch.object(self.api, 'create', side_effect=observed):
            value = self.submit()
        self.assertEqual(value['state'], 'running')
        self.assertEqual(seen, [True])

    def test_lost_submit_reply_and_empty_working_disk_reconcile_same_job(self):
        create = self.api.create
        def lost(kind, value):
            result = create(kind, value)
            if kind == 'job':
                raise TimeoutError('simulated lost API reply after Job admission')
            return result
        with patch.object(self.api, 'create', side_effect=lost), self.assertRaises(TimeoutError):
            self.submit()
        original = next(v for (kind, _), v in self.api.objects.items() if kind == 'job')
        shutil.rmtree(self.root)
        cluster.recover(self.config, self.catalogue)
        result = self.submit()
        self.assertEqual(result['job_uid'], original['metadata']['uid'])
        self.assertEqual(result['request']['source_push']['pushed_at'], 90)
        self.assertEqual(len([k for k in self.api.objects if k[0] == 'job']), 1)

    def test_crash_before_submit_is_uncertain_and_never_blindly_recreated(self):
        create = self.api.create
        def refused(kind, value):
            if kind == 'job':
                raise TimeoutError('simulated request with unknown admission')
            return create(kind, value)
        with patch.object(self.api, 'create', side_effect=refused), self.assertRaises(TimeoutError):
            self.submit()
        shutil.rmtree(self.root)
        cluster.recover(self.config, self.catalogue)
        value = self.submit()
        self.assertEqual(value['state'], 'submission_unknown')
        self.assertFalse(any(kind == 'job' for kind, _ in self.api.objects))
        self.assertEqual(self.submit(), value)

    def test_failed_original_job_is_terminal_and_not_retried(self):
        value = self.submit()
        self.api.objects['job', value['job_name']]['status'] = {'conditions': [{'type': 'Failed', 'status': 'True'}]}
        value = self.submit()
        self.assertEqual(value['state'], 'failed')
        created = self.api.created
        self.assertEqual(self.submit(), value)
        self.assertEqual(self.api.created, created)

    def test_unchanged_job_observation_never_rewrites_durable_request_or_effect(self):
        first = self.submit()
        with patch.object(cluster, 'write_json', side_effect=AssertionError('unchanged journal write')):
            self.assertEqual(self.submit(), first)
        self.api.objects['job', first['job_name']]['status'] = {'conditions': [{'type': 'Failed', 'status': 'True'}]}
        failed = self.submit()
        with patch.object(cluster, 'write_json', side_effect=AssertionError('terminal journal write')):
            self.assertEqual(self.submit(), failed)

    def test_configuration_upgrade_observes_original_job_and_clock(self):
        original = self.submit()
        self.config['cluster']['runner_image'] = 'registry.example/runner@sha256:' + 'e' * 64
        self.config['cluster']['config_map'] = 'android-config-new'
        created = self.api.created
        result = self.submit()
        self.assertEqual(result['job_uid'], original['job_uid'])
        self.assertEqual(result['request']['source_push']['pushed_at'], 90)
        self.assertEqual(result['job_definition'], original['job_definition'])
        self.assertEqual(self.api.created, created)

    def test_legacy_effect_uses_uid_and_original_immutable_configuration(self):
        original = self.submit()
        self.api.create('configmap', {'metadata': {'name': 'android-config'}, 'immutable': True,
            'data': {'android-agent.json': json.dumps(self.config)}})
        marker = json.loads(self.marker.read_text()); marker.pop('job_definition')
        release.write_json(self.marker, marker)
        self.config['cluster']['runner_image'] = 'registry.example/runner@sha256:' + 'e' * 64
        self.config['cluster']['config_map'] = 'android-config-new'
        self.assertEqual(self.submit()['job_uid'], original['job_uid'])
        self.api.objects['configmap', 'android-config']['immutable'] = False
        with self.assertRaisesRegex(ValueError, 'immutable Android configuration'):
            self.submit()
        self.api.objects['configmap', 'android-config']['immutable'] = True
        self.api.objects['job', original['job_name']]['metadata']['uid'] = 'replacement'
        with self.assertRaisesRegex(ValueError, 'Job identity changed'):
            self.submit()

    def test_new_request_cannot_use_a_different_configuration(self):
        self.config['cluster']['runner_image'] = 'registry.example/runner@sha256:' + 'e' * 64
        with self.assertRaisesRegex(ValueError, 'request configuration changed'):
            self.submit()
        self.assertFalse(any(kind == 'job' for kind, _ in self.api.objects))

    def test_rejected_promotion_is_archived_without_poisoning_later_intake(self):
        event = {'project': 'gcoms', 'ref': 'refs/tags/android-release/' + 'a' * 64,
                 'commit': 'b' * 40, 'pushed_at': 150, 'server_event_id': 'c' * 64}
        release.write_json(self.root / 'events/invalid.json', event)
        with patch.object(cluster, 'ingest'), patch.object(cluster, 'source_sync'), \
             patch.object(cluster, 'promotion_manifest', side_effect=FileNotFoundError):
            self.assertEqual(cluster.tick(self.config, self.api, self.catalogue)['state'], 'idle')
        marker = next((self.root / 'cluster-effects').glob('*.json'))
        rejected = json.loads(marker.read_text())
        self.assertEqual(rejected['state'], 'failed')
        self.assertEqual(rejected['request']['source_push'], event)
        descriptor = self.catalogue.lookup('checkpoints', 'rejection/' + rejected['request']['request_id'])
        self.assertEqual(self.archive.read_record(descriptor), rejected)
        with patch.object(cluster, 'ingest'), patch.object(cluster, 'source_sync') as sync:
            cluster.tick(self.config, self.api, self.catalogue)
        sync.assert_not_called()
        self.assertFalse(any(kind == 'job' for kind, _ in self.api.objects))

    def test_cached_preparation_constraint_is_bound_and_recovered_without_reexecution(self):
        self.request['require_cached'] = True
        self.request['request_id'] = hashlib.sha256(release.canonical(
            {key: value for key, value in self.request.items() if key != 'request_id'})).hexdigest()
        path = self.root / 'request.json'
        release.write_json(path, self.request)
        checksum = hashlib.sha256(release.canonical(self.request)).hexdigest()
        with patch.object(cluster, 'Catalogue', return_value=self.catalogue), \
                patch.object(cluster, 'prepare_release', return_value={'prepared_id': 'a' * 64}) as action:
            result = cluster.execute(self.config, path, checksum)
            self.assertEqual(result['state'], 'prepared')
            action.assert_called_once_with(self.config, self.request['manifest'], require_cached=True)
            (self.root / 'cluster-results' / (self.request['request_id'] + '.json')).unlink()
            self.assertEqual(cluster.execute(self.config, path, checksum), result)
            action.assert_called_once()

    def test_failed_execution_is_archived_and_cannot_repeat_after_local_result_loss(self):
        path = self.root / 'request.json'
        release.write_json(path, self.request)
        checksum = hashlib.sha256(release.canonical(self.request)).hexdigest()
        with patch.object(cluster, 'Catalogue', return_value=self.catalogue), \
             patch.object(cluster, 'prepare_release', side_effect=RuntimeError('private failed action')) as action:
            result = cluster.execute(self.config, path, checksum)
            self.assertEqual(result['state'], 'failed')
            diagnostic = self.root / 'cluster-failures' / (self.request['request_id'] + '.json')
            self.assertEqual(diagnostic.stat().st_mode & 0o777, 0o600)
            self.assertIn('private failed action', json.loads(diagnostic.read_text())['traceback'])
            self.assertNotIn('private failed action', json.dumps(result))
            (self.root / 'cluster-results' / (self.request['request_id'] + '.json')).unlink()
            self.assertEqual(cluster.execute(self.config, path, checksum), result)
        action.assert_called_once()
        descriptor = self.catalogue.lookup('checkpoints', 'result/' + self.request['request_id'])
        self.assertEqual(self.archive.read_record(descriptor), result)

    def test_complete_job_recovers_its_archived_result_from_empty_result_cache(self):
        value = self.submit()
        result = {'schema': 1, 'request_id': self.request['request_id'],
                  'request_sha256': hashlib.sha256(release.canonical(self.request)).hexdigest(),
                  'state': 'prepared', 'result': {'prepared_id': 'a' * 64}}
        self.catalogue.bind('checkpoints', 'result/' + self.request['request_id'], self.archive.publish_record(result))
        self.api.objects['job', value['job_name']]['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}]}
        value = self.submit()
        self.assertEqual(value['state'], 'complete')
        self.assertEqual(value['result'], result)

    def test_missing_or_changed_result_never_becomes_a_completed_release(self):
        value = self.submit()
        self.api.objects['job', value['job_name']]['status'] = {'conditions': [{'type': 'Complete', 'status': 'True'}]}
        with self.assertRaisesRegex(ValueError, 'no archived result'):
            self.submit()
        result = {'request_id': self.request['request_id'], 'request_sha256': 'bad', 'state': 'prepared'}
        release.write_json(self.root / 'cluster-results' / (self.request['request_id'] + '.json'), result)
        with self.assertRaisesRegex(ValueError, 'exact result'):
            self.submit()

    def test_recovery_rejects_changed_configuration_or_injected_paths(self):
        pointer = cluster.checkpoint(self.config, self.catalogue)
        original = self.archive.read_record(pointer)
        (self.root / 'source-cursors.json').unlink()
        changed = dict(self.config, state=str(self.root / 'changed'))
        with self.assertRaisesRegex(ValueError, 'configuration changed'):
            cluster.recover(changed, self.catalogue)
        original['files']['../outside.json'] = {'bad': True}
        descriptor = self.archive.publish_record(original)
        with patch.object(self.catalogue, 'lookup', return_value=descriptor):
            with self.assertRaisesRegex(ValueError, 'unsafe coordinator'):
                cluster.recover(self.config, self.catalogue)

    def test_job_has_no_retry_and_bounded_resources_and_pinned_runtime(self):
        value = cluster.job(self.config, self.request, self.root / 'request.json')
        spec = value['spec']; pod = spec['template']['spec']
        self.assertEqual(spec['backoffLimit'], 0)
        self.assertEqual(spec['activeDeadlineSeconds'], 3600)
        self.assertEqual(pod['restartPolicy'], 'Never')
        self.assertEqual(pod['containers'][0]['resources']['limits']['cpu'], '1')
        self.assertIn({'name': 'scratch', 'emptyDir': {'sizeLimit': '128Mi'}}, pod['volumes'])
        self.assertIn({'name': 'scratch', 'mountPath': '/work'}, pod['containers'][0]['volumeMounts'])
        self.assertIn({'name': 'TMPDIR', 'value': '/work'}, pod['containers'][0]['env'])
        self.config['cluster']['runner_image'] = 'registry.example/runner:latest'
        with self.assertRaisesRegex(ValueError, 'digest-pinned'):
            cluster.job(self.config, self.request, self.root / 'request.json')

    def test_image_warming_cannot_read_source_archive_or_cluster_credentials(self):
        self.config['forgejo']['token_file'] = '/credentials/source/token'
        self.config['cluster']['builder_image'] = 'registry.example/compiler@sha256:' + 'b' * 64
        rendered = cluster.workloads(self.config, 'registry.example/coordinator@sha256:' + 'a' * 64, 'source-reader')
        warmer, coordinator = rendered['items']
        pod = warmer['spec']['template']['spec']
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertNotIn('volumes', pod)
        self.assertTrue(all('volumeMounts' not in c for c in pod['containers']))
        self.assertEqual({c['image'] for c in pod['containers']}, {
            'registry.example/coordinator@sha256:' + 'a' * 64,
            self.config['cluster']['runner_image'], self.config['cluster']['builder_image']})
        self.assertEqual(coordinator['spec']['replicas'], 1)
        with self.assertRaisesRegex(ValueError, 'digest-pinned'):
            cluster.workloads(self.config, 'registry.example/coordinator:latest', 'source-reader')
        self.config['cluster']['builder_image'] = 'registry.example/compiler:latest'
        with self.assertRaisesRegex(ValueError, 'digest-pinned'):
            cluster.workloads(self.config, 'registry.example/coordinator@sha256:' + 'a' * 64, 'source-reader')

    def test_updated_operations_are_mounted_for_execution_and_persistent_coordination(self):
        # The image can retain its tools/compiler while a separately pinned
        # operation revision changes. Omitting this mount ran stale image code
        # and failed the real adapter hash gate before preparation began.
        self.config['cluster']['runtime_config_map'] = 'android-runtime-new'
        self.config['forgejo']['token_file'] = '/credentials/source/token'
        value = cluster.job(self.config, self.request, self.root / 'request.json')
        warmer, coordinator = cluster.workloads(self.config,
            'registry.example/coordinator@sha256:' + 'a' * 64, 'source-reader')['items']
        for resource in (value, coordinator):
            pod = resource['spec']['template']['spec']
            self.assertIn({'name': 'runtime', 'configMap': {'name': 'android-runtime-new', 'defaultMode': 0o555}}, pod['volumes'])
            self.assertIn({'name': 'runtime', 'mountPath': '/opt/gcoms/scripts', 'readOnly': True},
                          pod['containers'][0]['volumeMounts'])
        self.assertNotIn('volumes', warmer['spec']['template']['spec'])
        self.assertEqual(value['spec']['template']['spec']['containers'][0]['image'],
                         self.config['cluster']['runner_image'])

    def test_mounted_askpass_is_executable_and_failed_advertisement_is_retained(self):
        self.config['cluster']['runtime_config_map'] = 'android-runtime-new'
        pod = cluster.job(self.config, self.request, self.root / 'request.json')['spec']['template']['spec']
        mode = next(v for v in pod['volumes'] if v['name'] == 'runtime')['configMap'].get('defaultMode', 0o644)
        helper = self.root / 'askpass.py'
        helper.write_bytes(Path(cluster.__file__).with_name('android_release_git_askpass.py').read_bytes())
        helper.chmod(mode)
        reply = subprocess.check_output([str(helper), 'Username for test'], timeout=5)
        self.assertTrue(reply.strip())
        log = self.root / 'transport.log'
        def fail(_argv, **kwargs):
            Path(kwargs['log']).write_text('transport failure evidence\n')
            raise RuntimeError('git failed')
        with patch.object(cluster, 'command', side_effect=fail), self.assertRaises(RuntimeError):
            cluster.advertised_refs(self.root, ['refs/heads/main'], {}, log)
        self.assertIn('transport failure evidence', log.read_text())
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_sigterm_unwinds_active_coordinator_ownership(self):
        marker = self.root / 'released'
        code = '''import os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import android_release_cluster as cluster
def work(config,fence):
 try:os.kill(os.getpid(),signal.SIGTERM)
 finally:Path(sys.argv[2]).write_text('released')
cluster.supervise=work
cluster.serve({})
'''
        result = subprocess.run([sys.executable, '-c', code, str(Path(cluster.__file__).parent), str(marker)],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text(), 'released')

    def test_source_mirrors_refuse_workstation_paths_and_wrong_origin(self):
        self.config['sources']['gcoms']['repository'] = '/workstation/old.git'
        with self.assertRaisesRegex(ValueError, 'owned source directory'):
            cluster.source_sync(self.config)
        self.config['sources']['gcoms']['repository'] = str(self.root / 'sources/gcoms.git')
        (self.root / 'sources/gcoms.git').mkdir(parents=True)
        with patch.object(cluster, 'git', return_value=b'https://other.example/repo.git\n'):
            with self.assertRaisesRegex(ValueError, 'changed origin'):
                cluster.source_sync(self.config)

    def test_existing_intake_boundary_cannot_be_reinitialized(self):
        with self.assertRaisesRegex(ValueError, 'preserve the existing'):
            cluster.initialize(self.config, client=object())


if __name__ == '__main__':
    unittest.main()
