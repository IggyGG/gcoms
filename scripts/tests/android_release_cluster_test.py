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
        request = {'schema': 1, 'operation': 'prepare', 'manifest': {'pushed_at': 100},
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
            release.command(['/bin/true'], log=kwargs['log'])
            logs.append(kwargs['log'])
        with patch.object(cluster, 'command', side_effect=executed), \
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
            if 'fetch' in argv:
                argv[argv.index('origin')] = str(origin)
            return original(argv, **kwargs)
        with patch.object(cluster, 'command', side_effect=transport):
            cluster.source_sync(self.config)
        mirror = self.config['sources']['gcoms']['repository']
        refs = release.git(mirror, 'for-each-ref', '--format=%(refname)').decode().splitlines()
        self.assertEqual(set(refs), {'refs/heads/main', 'refs/heads/agent/android',
                                   'refs/tags/android-release/' + 'a' * 64})

    def test_source_sync_rejects_wildcard_before_git(self):
        self.config['sources']['gcoms']['ref'] = 'refs/heads/*'
        with patch.object(cluster, 'command') as command, self.assertRaisesRegex(ValueError, 'exact branch'):
            cluster.source_sync(self.config)
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
        self.config['cluster']['runner_image'] = 'registry.example/runner:latest'
        with self.assertRaisesRegex(ValueError, 'digest-pinned'):
            cluster.job(self.config, self.request, self.root / 'request.json')

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
