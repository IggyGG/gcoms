"""Original push clocks survive archive outages, duplicate forwarding and recovery."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if sys.platform == 'win32':
    raise unittest.SkipTest('POSIX Android deployment orchestration')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release_outbox as outbox
from android_release_store_test import S3


def event(**changes):
    value = {'schema': 1, 'project': 'gcoms', 'repository': 'ghost-local/gcoms',
             'ref': 'refs/heads/main', 'commit': 'a' * 40, 'pushed_at': 1788256800,
             'nonce': '4f77d441-d1fa-4508-ac7b-d77ca487a123'}
    return json.dumps(value | changes).encode()


class ServerOutbox(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # The hook compares its physical cwd with the configured repository.
        self.root = Path(temporary.name).resolve()
        self.directory = self.root / 'outbox'
        self.directory.mkdir(mode=0o700)
        self.config = {'archive': {'endpoint': 'https://fsn1.your-objectstorage.com',
            'region': 'fsn1', 'bucket': 'android-test-archive', 'prefix': 'android-release'},
            'sources': {'gcoms': {'project': 'gcoms', 'cluster_repository': 'ghost-local/gcoms'}},
            'event_directory': str(self.root / 'events')}
        self.client = S3()
        self.client.list_objects_v2 = lambda **kw: {'Contents': [
            {'Key': key} for key in sorted(self.client.objects) if key.startswith(kw['Prefix'])]}
        self.archive = outbox.archive_for(self.config, self.client)

    def put(self, raw=None):
        raw = event() if raw is None else raw
        path = self.directory / (hashlib.sha256(raw).hexdigest() + '.json')
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def test_delayed_forward_and_empty_cache_keep_original_clock(self):
        original = event()
        path = self.put(original)
        self.assertEqual(outbox.drain(self.directory, self.archive), 1)
        self.assertFalse(path.exists())
        received = outbox.ingest(self.config, self.archive)
        self.assertEqual(received[0]['pushed_at'], 1788256800)
        self.assertEqual(received[0]['server_event_id'], hashlib.sha256(original).hexdigest())
        self.assertEqual(outbox.ingest(self.config, self.archive), [])
        for cached in (self.root / 'events').iterdir():
            cached.unlink()
        self.assertEqual(outbox.ingest(self.config, self.archive), received)

    def test_upload_failure_keeps_original_file_for_retry(self):
        path = self.put()
        before = path.read_bytes()
        with patch.object(self.archive, 'publish_record', side_effect=OSError('archive unavailable')):
            with self.assertRaises(OSError):
                outbox.drain(self.directory, self.archive)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(outbox.drain(self.directory, self.archive), 1)

    def test_crash_after_upload_reuses_verified_version(self):
        path = self.put()
        with patch.object(outbox.os, 'unlink', side_effect=OSError('crash before acknowledgement')):
            with self.assertRaises(OSError):
                outbox.drain(self.directory, self.archive)
        self.assertTrue(path.exists())
        versions = self.client.sequence
        self.assertEqual(outbox.drain(self.directory, self.archive), 1)
        self.assertEqual(self.client.sequence, versions)

    def test_changed_clock_cannot_reuse_original_receipt(self):
        value = outbox.receipt(event())
        value['original_b64'] = base64.b64encode(event(pushed_at=1788256801)).decode()
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            outbox.restore(value)

    def test_bounded_private_files_and_repository_binding(self):
        for raw in (event(repository='other/gcoms'), event(project=[]),
                    event(pushed_at=True), event(pushed_at=9999999999),
                    event(ref='refs/heads/agent/../../escape'), b'x' * 2049):
            with self.subTest(raw=raw[:60]), self.assertRaises(ValueError):
                outbox.decode(raw)
        path = self.put()
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private regular'):
            outbox.drain(self.directory, self.archive)
        path.unlink()
        private = self.root / 'outside'
        private.write_bytes(event())
        path.symlink_to(private)
        with self.assertRaises(OSError):
            outbox.drain(self.directory, self.archive)
        self.assertEqual(private.read_bytes(), event())
        self.assertEqual(self.client.sequence, 0)

    def test_changed_local_event_and_corrupt_archive_are_refused(self):
        self.put()
        outbox.drain(self.directory, self.archive)
        outbox.ingest(self.config, self.archive)
        cached = next((self.root / 'events').iterdir())
        cached.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'original source event changed'):
            outbox.ingest(self.config, self.archive)
        cached.unlink()
        self.client.corrupt = next(iter(self.client.objects))
        # The retained original receipt remains valid even if its remote object
        # is later damaged. A truly empty receipt cache must detect that damage.
        self.assertEqual(len(outbox.ingest(self.config, self.archive)), 1)
        cached.unlink()
        for receipt in (self.root / 'server-receipts').iterdir(): receipt.unlink()
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            outbox.ingest(self.config, self.archive)

    def test_unchanged_poll_reuses_verified_receipts_without_archive_reads_or_writes(self):
        self.put(); outbox.drain(self.directory, self.archive)
        first = outbox.ingest(self.config, self.archive)
        with patch.object(self.client, 'head_object', side_effect=AssertionError('repeated HEAD')), \
                patch.object(self.client, 'get_object', side_effect=AssertionError('repeated GET')), \
                patch.object(outbox, 'write_json', side_effect=AssertionError('unchanged write')):
            self.assertEqual(outbox.ingest(self.config, self.archive), [])
        cached = next((self.root / 'server-receipts').iterdir())
        value = json.loads(cached.read_text()); value['original_b64'] = base64.b64encode(event(pushed_at=1788256801)).decode()
        cached.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            outbox.ingest(self.config, self.archive)
        self.assertEqual(first[0]['pushed_at'], 1788256800)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux Forgejo server hook uses procfs')
    def test_real_server_hook_persists_once_without_network_credentials(self):
        repositories = self.root / 'repos'
        repository = repositories / 'ghost-local/gcoms.git'
        repository.mkdir(parents=True)
        source = Path(__file__).resolve().parents[1] / 'android_release_outbox_hook.sh'
        script = source.read_text().replace('/data/git/gitea-repositories', str(repositories))
        script = script.replace('/data/android-release/outbox', str(self.directory))
        hook = self.root / 'hook.sh'
        hook.write_text(script)
        updates = ('0' * 40 + ' ' + 'a' * 40 + ' refs/heads/main\n'
                   + '0' * 40 + ' ' + 'b' * 40 + ' refs/heads/agent/unsafe"ref\n')
        subprocess.run(['sh', str(hook)], cwd=repository, input=updates, text=True, check=True)
        paths = list(self.directory.glob('*.json'))
        self.assertEqual(len(paths), 1)
        value = outbox.decode(paths[0].read_bytes())
        self.assertEqual(value['commit'], 'a' * 40)
        self.assertEqual(paths[0].stem, value['server_event_id'])
        self.assertEqual(outbox.drain(self.directory, self.archive), 1)
