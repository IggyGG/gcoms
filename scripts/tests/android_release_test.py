"""Release regressions use a simulated adapter, never the production hub."""
import json
import base64
import os
from pathlib import Path
import subprocess
import socket
import struct
import sys
import tempfile
import time
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release as release
from android_release_host import aligned_loads, pinned_resolution, ready, route_expiry
import android_release_queue as queue
import android_release_setup as setup
import android_release_host as host
import android_release_hub as hub
import android_release_network as network


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
                        'apk': ['agent'], 'hub': ['gchat', 'gcoms'], 'worker': ['drone', 'gcoms'],
                        'controller': ['drone', 'gcoms', 'gchat']}
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

    def test_prepared_promotion_freezes_sources_and_never_builds(self):
        self.config['require_prepared'] = True
        prepared = release.prepare_release(self.config)
        repo = Path(self.config['sources']['agent']['repository'])
        (repo / 'mobile/android/agent/source.kt').write_text('newer unprepared source')
        self.git(repo, 'commit', '-qam', 'newer')
        manifest = release.promotion_manifest(self.config, prepared['prepared_id'], time.time())
        self.assertEqual(manifest['sources'], prepared['sources'])
        with patch.object(release, 'build', side_effect=AssertionError('promotion compiled code')):
            result = release.deploy(self.config, manifest)
        self.assertEqual(result['state'], 'live')
        self.assertTrue(all(a['cache_hit'] for a in result['artifacts'].values()))

    def test_prepared_receipt_missing_or_corrupt_artifact_blocks_promotion(self):
        prepared = release.prepare_release(self.config)
        path = Path(self.config['state']) / 'artifacts/sdk' / prepared['inputs']['sdk'] / 'artifact'
        path.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            release.promotion_manifest(self.config, prepared['prepared_id'], time.time())
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            release.promotion_manifest(self.config, prepared['prepared_id'], time.time())
        self.assertFalse((Path(self.config['state']) / 'live.json').exists())

    def test_unprepared_live_manifest_is_refused(self):
        self.config['require_prepared'] = True
        with self.assertRaisesRegex(ValueError, 'immutable prepared promotion'):
            release.deploy(self.config, release.freeze(self.config, time.time()))

    def test_required_functional_rollback_rejects_byte_only_restoration(self):
        self.config.update(require_functional_rollback=True, fault='missing_worker')
        _manifest, result = self.run_release()
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['rollback'], 'failed')
        self.assertEqual(result['rollback_failure_type'], 'ValueError')
        self.assertFalse((Path(self.config['state']) / 'live.json').exists())

    def test_source_push_requests_preparation_without_activation(self):
        self.config.update(require_prepared=True, warm_unit='gcoms-android-warm.service')
        event_dir = self.root / 'events'
        event_dir.mkdir()
        self.config['event_directory'] = str(event_dir)
        for name, row in self.config['sources'].items():
            row['project'] = name
        event = {'project': 'agent', 'ref': 'HEAD', 'commit': 'a' * 40, 'pushed_at': int(time.time())}
        (event_dir / 'source.json').write_text(json.dumps(event))
        with patch.object(queue, 'deploy', side_effect=AssertionError('source push activated')), \
             patch.object(queue, 'command') as scheduling:
            self.assertEqual(queue.consume(self.config)['state'], 'preparation_requested')
        self.assertEqual(scheduling.call_args.args[0],
                         ['systemctl', '--user', 'start', '--no-block', 'gcoms-android-warm.service'])
        self.assertFalse((Path(self.config['state']) / 'latest.json').exists())

    def test_invalid_promotion_is_consumed_with_original_clock(self):
        event_dir = self.root / 'events'
        event_dir.mkdir()
        self.config.update(event_directory=str(event_dir), require_prepared=True)
        for name, row in self.config['sources'].items():
            row['project'] = name
        pushed = int(time.time()) - 20
        event = {'project': 'gcoms', 'ref': queue.PROMOTION_PREFIX + 'a' * 64,
                 'commit': 'b' * 40, 'pushed_at': pushed}
        (event_dir / 'promotion.json').write_text(json.dumps(event))
        result = queue.consume(self.config)
        self.assertEqual(result['failure_stage'], 'promotion_validation')
        self.assertGreaterEqual(result['elapsed_seconds'], 20)
        self.assertEqual(queue.consume(self.config)['state'], 'idle')

    def test_promotion_guard_rejects_rewrite_delete_and_annotated_tag(self):
        repo = Path(self.config['sources']['gcoms']['repository'])
        commit = self.git(repo, 'rev-parse', 'HEAD').decode().strip()
        hook = Path(release.__file__).with_name('android_release_pre_receive.sh')
        ref = queue.PROMOTION_PREFIX + 'a' * 64
        zero = '0' * 40
        def guard(before, after):
            return subprocess.run(['sh', str(hook)], cwd=repo,
                input=f'{before} {after} {ref}\n', text=True, capture_output=True).returncode
        self.assertEqual(guard(zero, commit), 0)
        self.assertNotEqual(guard(commit, commit), 0)
        self.assertNotEqual(guard(commit, zero), 0)
        self.git(repo, 'tag', '-am', 'annotated', 'annotated')
        self.assertNotEqual(guard(zero, self.git(repo, 'rev-parse', 'annotated').decode().strip()), 0)

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

    def test_new_input_key_keeps_existing_companion_compiler_paths(self):
        self.config['build_directory'] = str(self.root / 'build')
        root = self.root / 'build' / 'sdk'
        legacy = root / ('a' * 64)
        legacy.mkdir(parents=True)
        self.git(self.root, 'clone', '-q', self.config['sources']['gcoms']['repository'], str(legacy / 'gcoms'))
        manifest = release.freeze(self.config, time.time())
        first = host.source_workspace(self.config, manifest, 'sdk')
        self.assertEqual(first.resolve(), legacy.resolve())
        manifest['inputs']['sdk'] = 'b' * 64
        second = host.source_workspace(self.config, manifest, 'sdk')
        self.assertEqual(second.resolve(), first.resolve())

    def test_added_target_abi_rebuilds_only_its_downloadable_worker_input(self):
        self.config['targets'][0]['abi'] = 'x86_64'
        first = release.freeze(self.config, time.time())
        self.config['targets'].append({'id': 'android-arm', 'kind': 'android', 'abi': 'arm64-v8a'})
        second = release.freeze(self.config, time.time())
        self.assertNotEqual(first['inputs']['worker'], second['inputs']['worker'])
        self.assertTrue(all(first['inputs'][c] == second['inputs'][c]
                            for c in release.COMPONENTS if c != 'worker'))


class Maintenance(unittest.TestCase):
    def test_oversized_private_frame_is_rejected_before_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'hub.sock'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path)); server.listen()
                def respond():
                    with server.accept()[0] as stream:
                        size = struct.unpack('!I', hub.receive(stream, 4))[0]
                        hub.receive(stream, size)
                        stream.sendall(struct.pack('!I', hub.FRAME_LIMIT + 1))
                thread = threading.Thread(target=respond); thread.start()
                with self.assertRaisesRegex(ValueError, 'exceeds bounds'):
                    hub.exchange(path, 'a' * 64, os.getpid(), {'kind': 'identify'})
                thread.join(timeout=2); self.assertFalse(thread.is_alive())

    def test_private_socket_checks_process_identity_and_bounded_framing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'hub.sock'
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path)); server.listen()
            self.addCleanup(server.close)
            def respond():
                with server.accept()[0] as stream:
                    size = struct.unpack('!I', hub.receive(stream, 4))[0]
                    request = json.loads(hub.receive(stream, size))
                    self.assertEqual(request['request']['kind'], 'identify')
                    data = json.dumps({'version': 3, 'instance_id': 'a' * 64,
                        'response': {'kind': 'instance', 'instance': {'id': 'a' * 64}}}).encode()
                    stream.sendall(struct.pack('!I', len(data)) + data)
            thread = threading.Thread(target=respond); thread.start()
            result = hub.exchange(path, 'a' * 64, os.getpid(), {'kind': 'identify'})
            thread.join(timeout=2); self.assertFalse(thread.is_alive())
            self.assertEqual(result['instance']['id'], 'a' * 64)
            with self.assertRaisesRegex(ValueError, 'another hub process'):
                hub.exchange(path, 'a' * 64, os.getpid() + 1, {'kind': 'identify'})

    def test_checkpoint_disconnects_before_exit_and_rejects_a_busy_owner(self):
        attached = ({'pid': 123}, {'chatEndpoint': 'private', 'instanceId': 'a' * 64}, {'bootId': 'old'})
        operations = []
        def rpc(_endpoint, _instance, _pid, request):
            action = request.get('request', {}).get('action', request['kind'])
            operations.append(action)
            if action == 'disconnect': return {'kind': 'snapshot', 'snapshot': {'instance': {'protocolLocked': True}}}
            return {'kind': 'update', 'result': {'state': 'ready', 'process_id': 123, 'boot_id': 'old'}}
        with patch.object(hub, 'eligible', return_value=attached), patch.object(hub, 'exchange', side_effect=rpc), \
             patch.object(hub, 'manager') as manager:
            self.assertEqual(hub.checkpoint({'hub_unit': 'gchat-test.service'}, 'b' * 64), (attached[0], 'old'))
            self.assertEqual(operations, ['heartbeat', 'prepare', 'disconnect', 'exit'])
            manager.assert_called_once_with('gchat-test.service', 'stop')
        with patch.object(hub, 'eligible', return_value=attached), \
             patch.object(hub, 'exchange', return_value={'kind': 'update', 'result': {'state': 'busy'}}), \
             patch.object(hub, 'manager') as manager:
            with self.assertRaisesRegex(ValueError, 'busy'): hub.checkpoint({'hub_unit': 'gchat-test.service'}, 'b' * 64)
            manager.assert_not_called()

    def test_retained_hub_selection_preserves_live_protocol_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root / 'input'; binary.write_bytes(b'qualified executable')
            profile = root / 'profile.gcprotocol'; profile.write_bytes(b'latest durable ratchet')
            retained = hub.install_binary(root, binary); hub.select(root, retained)
            self.assertEqual(release.digest(root / 'active/gchat'), release.digest(binary))
            self.assertEqual(profile.read_bytes(), b'latest durable ratchet')
            with self.assertRaisesRegex(ValueError, 'escapes'): hub.select(root, binary)
            retained.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'differs'): hub.install_binary(root, binary)

    def test_reference_requires_real_sized_timely_source_bound_resume_and_load(self):
        proof = {'schema': 1, 'kind': 'android-runtime-qualification', 'inputs': {'sdk': 'a' * 64},
                 'observed_at': 100, 'vpn': {'state': 'connected'},
                 'android': {k: True for k in ('full_download_verified', 'loaded_worker_ready',
                                               'identity_preserved', 'resume_verified')},
                 'reference_transfer': {'bytes': 42 * 1024 * 1024, 'elapsed_seconds': 300,
                    'sha256_verified': True, 'current_process_verified': True}}
        self.assertEqual(network.reference(proof, proof['inputs'], now=101), proof)
        for changed in ({'inputs': {}}, {'observed_at': -86401},
                        {'vpn': {'state': 'disconnected'}}, {'android': {}},
                        {'reference_transfer': dict(proof['reference_transfer'], elapsed_seconds=361)},
                        {'reference_transfer': dict(proof['reference_transfer'], bytes=42000)}):
            with self.assertRaises(ValueError): network.reference(dict(proof, **changed), proof['inputs'], now=101)


if __name__ == '__main__':
    unittest.main()
