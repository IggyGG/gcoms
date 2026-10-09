"""Release regressions use a simulated adapter, never the production hub."""
import json
import base64
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release as release
from android_release_host import aligned_loads, pinned_resolution, ready, route_expiry
import android_release_queue as queue
import android_release_setup as setup
import android_release_host as host


ADAPTER = '''import hashlib,json,pathlib,sys,time
r=json.loads(pathlib.Path(sys.argv[-1]).read_text())
c=r['config'];m=r['manifest']
if 'component' in r:
 p=pathlib.Path(r['output']);p.mkdir(parents=True,exist_ok=True)
 if c.get('fault')=='apk_overlap':
  gate=pathlib.Path(c['state'])/'apk-started'
  if r['component']=='apk':gate.write_text('started after SDK and installer')
  if r['component']=='hub':
   until=time.monotonic()+3
   while not gate.exists():
    if time.monotonic()>until:raise RuntimeError('APK waited for independent hub')
    time.sleep(.01)
 (p/'artifact').write_bytes(r['component'].encode())
 (p/'receipt.json').write_text(json.dumps({'component':r['component'],'input_sha256':m['inputs'][r['component']],
   'sources':{n:m['sources'][n] for n in c['builds'][r['component']]['sources']},
   'files':{'artifact':hashlib.sha256((p/'artifact').read_bytes()).hexdigest()}}))
else:
 p=pathlib.Path(r['directory']);op=sys.argv[1]
 if op=='readiness':
  rows=[dict(t,healthy=True,matches=True,full_download_verified=True,loaded_worker_ready=True,
             identity_preserved=True) for t in m['targets']]
  if c.get('fault')=='missing_worker':rows[0]['loaded_worker_ready']=False
  (p/'live.json').write_text(json.dumps({'release_id':m['release_id'],'targets':rows}))
 if op=='rollback':
  (p/'rollback-observed').write_text('previous bytes with current app state')
  (p/'rollback.json').write_text(json.dumps({'previous_artifacts_verified':True,'functional_readiness_verified':False}))
 if op=='preflight' and c.get('fault')=='preflight':sys.exit(1)
'''


class Releases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        adapter = self.root / 'adapter.py'
        adapter.write_text(ADAPTER)
        sources = {}
        for name in ('gcoms', 'agent', 'dropship', 'gchat', 'drone'):
            repo = self.root / name
            repo.mkdir()
            self.git(repo, 'init', '-q')
            self.git(repo, 'config', 'user.name', 'Release regression')
            self.git(repo, 'config', 'user.email', 'release@example.invalid')
            path = repo / ('mobile/android/agent/source.kt' if name == 'agent' else 'source.rs')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('first source')
            self.git(repo, 'add', '.')
            self.git(repo, 'commit', '-qm', 'first')
            sources[name] = {'repository': str(repo), 'ref': 'HEAD'}
        dependencies = {'sdk': ['gcoms'], 'installer': ['dropship', 'gcoms'],
                        'apk': ['agent'], 'hub': ['gchat', 'gcoms'], 'worker': ['drone', 'gcoms']}
        self.config = {'state': str(self.root / 'state'), 'sources': sources,
                       'toolchain': {'rust': 'pinned', 'ndk': 'pinned'},
                       'targets': [{'id': 'android-canary', 'kind': 'android'}],
                       'builds': {c: {'sources': dependencies[c], 'command': [sys.executable, str(adapter)]}
                                  for c in release.COMPONENTS},
                       'actions': {n: [sys.executable, str(adapter), n]
                                   for n in ('preflight', 'verify', 'activate', 'readiness', 'rollback')}}

    def git(self, repo, *args):
        return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.PIPE)

    def run_release(self):
        manifest = release.freeze(self.config, time.time())
        return manifest, release.deploy(self.config, manifest)

    def test_full_transaction_and_unchanged_build_reuse(self):
        first, result = self.run_release()
        self.assertEqual(result['state'], 'live')
        self.assertTrue(all(not a['cache_hit'] for a in result['artifacts'].values()))
        _, second = self.run_release()
        self.assertEqual(second['state'], 'live')
        self.assertTrue(all(a['cache_hit'] for a in second['artifacts'].values()))
        self.assertLess(second['elapsed_seconds'], 600)
        # APK-only edits do not rebuild the SDK, installer, hub or worker.
        repo = Path(self.config['sources']['agent']['repository'])
        (repo / 'mobile/android/agent/source.kt').write_text('changed Android source')
        self.git(repo, 'commit', '-qam', 'Android change')
        _, third = self.run_release()
        self.assertFalse(third['artifacts']['apk']['cache_hit'])
        self.assertTrue(all(third['artifacts'][c]['cache_hit'] for c in release.COMPONENTS if c != 'apk'))

    def test_missing_real_worker_requires_restoration(self):
        self.config['fault'] = 'missing_worker'
        manifest, result = self.run_release()
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['rollback'], 'previous_artifacts_verified')
        self.assertTrue((Path(self.config['state']) / 'runs' / manifest['release_id'] / 'rollback-observed').is_file())
        self.assertFalse((Path(self.config['state']) / 'live.json').exists())

    def test_preflight_failure_does_not_build_or_mutate(self):
        self.config['fault'] = 'preflight'
        _, result = self.run_release()
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['artifacts'], {})
        self.assertNotIn('activation_started', result)

    def test_original_push_time_is_not_reset_by_retry(self):
        manifest = release.freeze(self.config, time.time() - 601)
        result = release.deploy(self.config, manifest)
        self.assertEqual(result['state'], 'failed')
        self.assertGreaterEqual(result['elapsed_seconds'], 600)
        self.assertEqual(release.deploy(self.config, manifest), result)

    def test_corrupted_cache_is_never_an_artifact_pass(self):
        manifest, result = self.run_release()
        p = Path(self.config['state']) / 'artifacts/sdk' / manifest['inputs']['sdk'] / 'artifact'
        p.write_bytes(b'changed bytes')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            release.cached_artifact(self.config, 'sdk', manifest['inputs']['sdk'])

    def test_modified_manifest_and_changed_toolchain_refused(self):
        manifest = release.freeze(self.config, time.time())
        manifest['pushed_at'] += 1
        with self.assertRaises(ValueError):
            release.deploy(self.config, manifest)
        manifest = release.freeze(self.config, time.time())
        self.config['toolchain']['rust'] = 'different'
        with self.assertRaises(ValueError):
            release.deploy(self.config, manifest)

    def test_real_input_changes_invalidate_dependents(self):
        first = release.freeze(self.config, time.time())
        repo = Path(self.config['sources']['gcoms']['repository'])
        (repo / 'source.rs').write_text('changed protocol')
        self.git(repo, 'commit', '-qam', 'protocol change')
        second = release.freeze(self.config, time.time())
        self.assertTrue(all(first['inputs'][c] != second['inputs'][c] for c in release.COMPONENTS))

    def test_prose_and_apple_sources_do_not_invalidate_android(self):
        first = release.freeze(self.config, time.time())
        repo = Path(self.config['sources']['gcoms']['repository'])
        (repo / 'README.md').write_text('updated prose')
        apple = repo / 'mobile/apple/preview.swift'
        apple.parent.mkdir(parents=True)
        apple.write_text('Apple preview')
        self.git(repo, 'add', '.')
        self.git(repo, 'commit', '-qm', 'prose and Apple')
        second = release.freeze(self.config, time.time())
        self.assertEqual(first['inputs'], second['inputs'])

    def test_target_kind_and_inventory_cannot_bypass_android_readiness(self):
        manifest = {'release_id': 'r', 'targets': [{'id': 'a', 'kind': 'android'}]}
        for rows in ([], [{'id': 'a', 'kind': 'hub', 'healthy': True, 'matches': True}]):
            with self.assertRaises(ValueError):
                release.checked_targets(manifest, {'release_id': 'r', 'targets': rows})

    def test_deadline_uses_wall_and_monotonic_time(self):
        with patch.object(release.time, 'time', return_value=1000), patch.object(release.time, 'monotonic', return_value=20):
            deadline = release.Deadline(900)
        with patch.object(release.time, 'time', return_value=800), patch.object(release.time, 'monotonic', return_value=521):
            with self.assertRaises(TimeoutError):
                deadline.remaining()

    def test_timeout_terminates_a_hanging_command(self):
        began = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            release.command([sys.executable, '-c', 'import time;time.sleep(60)'], timeout=.05)
        self.assertLess(time.monotonic() - began, 3)

    def test_readiness_requires_current_payload_process_and_release(self):
        expected = {'release_id': 'r', 'apk_sha256': 'a', 'worker_sha256': 'w'}
        proof = dict(expected, process_id=123, full_download_verified=True,
                     admission_verified=True, loaded_worker_ready=True)
        ready(proof, expected, '123')
        for changed in ({'process_id': 122}, {'release_id': 'old'}, {'worker_sha256': 'other'},
                        {'loaded_worker_ready': False}, {'admission_verified': False}):
            with self.assertRaises(ValueError):
                ready(dict(proof, **changed), expected, '123')

    def test_native_load_segments_require_real_16k_alignment(self):
        aligned_loads('  LOAD 0x000000 0x000000 0x000000 0x1234 0x1234 R E 0x4000\n')
        for headers in ('', 'LOAD 0x0 0x0 0x0 0x1234 0x1234 R E 0x1000\n',
                        'LOAD 0x0 0x0 0x0 0x1234 0x1234 R E 0x4000\nLOAD 0x4000 0x4000 0x4000 0x100 0x100 RW 0x1000\n'):
            with self.assertRaises(ValueError):
                aligned_loads(headers)

    def test_actual_introduction_expiry_wins_over_longer_profile_ttl(self):
        raw = b'GCRB\x02\x02' + b'x' * 147 + (1000).to_bytes(8, 'big') + b'y' * 147 + (900).to_bytes(8, 'big')
        profile = {'expiresAtUnix': 9000, 'gc2RoutingBundleB64': base64.urlsafe_b64encode(raw).decode().rstrip('=')}
        self.assertEqual(route_expiry(profile), 900)
        for broken in (b'GCRB\x01\x02', raw[:-1], b'GCRB\x02\x00'):
            with self.assertRaises(ValueError):
                route_expiry({'gc2RoutingBundleB64': base64.urlsafe_b64encode(broken).decode()})

    def test_queue_preserves_original_push_clock_and_does_not_repeat_failure(self):
        self.config['fault'] = 'preflight'
        event_dir = self.root / 'events'
        event_dir.mkdir()
        self.config['event_directory'] = str(event_dir)
        for name, value in self.config['sources'].items():
            value['project'] = name
            value['ref'] = self.git(value['repository'], 'symbolic-ref', 'HEAD').decode().strip()
        source = self.config['sources']['agent']
        pushed_at = int(time.time()) - 20
        event = {'project': 'agent', 'ref': source['ref'], 'pushed_at': pushed_at,
                 'commit': self.git(source['repository'], 'rev-parse', 'HEAD').decode().strip()}
        (event_dir / 'push.json').write_text(json.dumps(event))
        result = queue.consume(self.config)
        self.assertEqual(result['state'], 'failed')
        self.assertGreaterEqual(result['elapsed_seconds'], 20)
        self.assertEqual(queue.consume(self.config)['state'], 'idle')
        saved = json.loads((Path(self.config['state']) / 'latest.json').read_text())
        self.assertEqual(saved['pushed_at'], pushed_at)

    def test_compile_environment_changes_invalidate_builds(self):
        first = release.freeze(self.config, time.time())
        self.config['environment'] = {'RUSTFLAGS': '-C target-feature=+changed'}
        after = release.freeze(self.config, time.time())
        self.assertTrue(all(first['inputs'][c] != after['inputs'][c] for c in release.COMPONENTS))

    def test_queued_push_preempts_only_owned_warming_before_deploy(self):
        self.config['warm_unit'] = 'gcoms-android-warm.service'
        with patch.object(queue, 'events', return_value=[(self.root / 'event.json',
                {'project': 'agent', 'ref': 'HEAD', 'commit': 'a' * 40, 'pushed_at': int(time.time())})]), \
             patch.object(queue, 'command') as stop, patch.object(queue, 'git', return_value=b'b' * 40):
            for value in self.config['sources'].values():
                value['project'] = 'agent'
            queue.consume(self.config)
        self.assertEqual(stop.call_count, 2)
        self.assertEqual(stop.call_args_list[0].args[0], ['systemctl', '--user', 'stop', 'gcoms-android-warm.service'])
        self.assertLessEqual(stop.call_args_list[0].kwargs['timeout'], 15)
        self.assertEqual(stop.call_args_list[1].args[0],
                         ['systemctl', '--user', 'start', '--no-block', 'gcoms-android-warm.service'])

    def test_setup_refuses_activating_oneshot_before_copying_runtime(self):
        with patch.object(setup.subprocess, 'run', return_value=SimpleNamespace(stdout='activating\n')):
            with self.assertRaisesRegex(ValueError, 'preserve the active'):
                setup.prepare(self.root / 'service')
        self.assertFalse((self.root / 'service').exists())

    def test_builder_cannot_claim_an_older_frozen_invocation(self):
        with self.assertRaisesRegex(ValueError, 'adapter changed'):
            host.build({'config': {'toolchain': {'builder_sha256': 'wrong'}},
                        'manifest': {}, 'component': 'sdk'})

    def test_modified_provisioning_adapter_is_refused_before_activation(self):
        file = self.root / 'adapter.py'
        self.config['runtime_sha256'] = {str(file): release.digest(file)}
        manifest = release.freeze(self.config, time.time())
        file.write_text('changed provisioning')
        with self.assertRaisesRegex(ValueError, 'adapter bytes changed'):
            release.deploy(self.config, manifest)
        self.assertFalse(Path(self.config['state']).exists())

    def test_local_sdk_resolution_preserves_committed_external_pins(self):
        original = b'[[package]]\nname="serde"\nversion="1"\nsource="registry+example"\nchecksum="a"\n'
        companion = original.replace(b'name="serde"', b'name="crypto"')
        pinned_resolution(original, companion, original + companion)
        for changed in (original.replace(b'version="1"', b'version="2"'),
                        original.replace(b'checksum="a"', b'checksum="different"')):
            with self.assertRaisesRegex(ValueError, 'frozen source lockfiles'):
                pinned_resolution(original, companion, changed)

    def test_apk_packaging_does_not_wait_for_independent_hub(self):
        self.config['fault'] = 'apk_overlap'
        _, result = self.run_release()
        self.assertEqual(result['state'], 'live')
        self.assertTrue((Path(self.config['state']) / 'apk-started').exists())


if __name__ == '__main__':
    unittest.main()
