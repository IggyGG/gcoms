"""Original server clocks, bounded pagination and restart-safe source intake."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

if sys.platform == 'win32':
    raise unittest.SkipTest('POSIX Android deployment orchestration')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release_source as source


def row(identity=12, ref='refs/heads/main', created='2026-09-01T10:00:00Z'):
    return {'id': identity, 'op_type': 'push_tag' if ref.startswith('refs/tags/') else 'commit_repo',
            'repo': {'full_name': 'ghost-local/gcoms'}, 'ref_name': ref, 'created': created,
            'content': json.dumps({'HeadCommit': {'Sha1': 'a' * 40,
                                               'Timestamp': '2001-01-01T00:00:00Z'}})}


class SourceIntake(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {'state': str(self.root / 'state'), 'event_directory': str(self.root / 'events'),
                       'sources': {'gcoms': {'project': 'gcoms', 'cluster_repository': 'ghost-local/gcoms'},
                                   'agent': {'project': 'gcoms', 'cluster_repository': 'ghost-local/gcoms'}}}
        (self.root / 'state').mkdir()
        self.cursor = self.root / 'state/source-cursors.json'
        self.cursor.write_text(json.dumps({'ghost-local/gcoms': 10}))

    def test_server_activity_clock_ignores_commit_date_and_delayed_poll(self):
        expected = 1788256800
        for observed in (expected + 30, expected + 86400):
            value = source.event(row(), 'ghost-local/gcoms', 'gcoms', now=observed)
            self.assertEqual(value['pushed_at'], expected)
            self.assertEqual(value['commit'], 'a' * 40)

    def test_promotion_keeps_actual_server_event_and_exact_tag(self):
        ref = source.PROMOTION + 'b' * 64
        value = source.event(row(ref=ref), 'ghost-local/gcoms', 'gcoms')
        self.assertEqual(value['ref'], ref)
        self.assertEqual(value['forgejo_activity_id'], 12)
        self.assertIsNone(source.event(row(ref=ref), 'ghost-local/gcoms', 'drone'))

    def test_missing_or_future_server_timestamp_is_refused(self):
        for created in (None, '2026-09-01T10:00:00', '2099-01-01T00:00:00Z'):
            with self.subTest(created=created), self.assertRaises(ValueError):
                source.event(row(created=created), 'ghost-local/gcoms', 'gcoms')

    def test_other_repository_cannot_inject_source_event(self):
        with self.assertRaisesRegex(ValueError, 'different repository'):
            source.event(row(), 'ghost-local/drone', 'gcoms')

    def test_nonpush_and_contentless_notification_do_not_create_a_clock(self):
        for change in ({'op_type': 'delete_tag'}, {'content': ''}, {'ref_name': 'refs/heads/unselected'},
                       {'ref_name': 'refs/heads/agent/quote"'}):
            self.assertIsNone(source.event(row() | change, 'ghost-local/gcoms', 'gcoms'))

    def test_cursor_requires_explicit_migration_boundary(self):
        self.cursor.unlink()
        with self.assertRaisesRegex(ValueError, 'migration cursor'):
            source.ingest(self.config, client=object())

    def test_restart_preserves_original_event_and_fsynced_cursor(self):
        class Client:
            def activities(self, repository, after):
                return [row()] if after < 12 else []
        first = source.ingest(self.config, Client())
        event_path = self.root / 'events/gcoms-12.json'
        original = event_path.read_bytes()
        self.assertEqual(len(first), 1)
        self.assertEqual(source.ingest(self.config, Client()), [])
        self.assertEqual(event_path.read_bytes(), original)
        # Simulate death after the durable event but before cursor publication.
        self.cursor.write_text(json.dumps({'ghost-local/gcoms': 10}))
        source.ingest(self.config, Client())
        self.assertEqual(event_path.read_bytes(), original)

    def test_failed_event_write_does_not_advance_cursor(self):
        class Client:
            def activities(self, repository, after): return [row()]
        before = self.cursor.read_bytes()
        with patch.object(source, 'write_json', side_effect=OSError('simulated storage failure')):
            with self.assertRaises(OSError): source.ingest(self.config, Client())
        self.assertEqual(self.cursor.read_bytes(), before)

    def test_changed_original_event_is_refused(self):
        class Client:
            def activities(self, repository, after): return [row()]
        source.ingest(self.config, Client())
        self.cursor.write_text(json.dumps({'ghost-local/gcoms': 10}))
        p = self.root / 'events/gcoms-12.json'
        value = json.loads(p.read_text());value['pushed_at'] += 1;p.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'original source event changed'):
            source.ingest(self.config, Client())

    def client(self):
        return source.Forgejo({'url': 'https://forgejo.example', 'token_file': '/unused'}, opener=object())

    def test_pagination_deduplicates_boundary_without_losing_pushes(self):
        client = self.client()
        pages = [[row(i) for i in range(210, 110, -1)],
                 [row(i) for i in range(112, 12, -1)]]
        with patch.object(client, 'read', side_effect=pages):
            result = client.activities('ghost-local/gcoms', 20)
        self.assertEqual([x['id'] for x in result], list(range(21, 211)))

    def test_backlog_over_bound_is_explicit(self):
        client = self.client()
        with patch.object(source, 'MAX_PAGES', 1), patch.object(client, 'read', return_value=[row(i) for i in range(200, 100, -1)]):
            with self.assertRaisesRegex(ValueError, 'cursor retained'):
                client.activities('ghost-local/gcoms', 10)

    def test_credentials_never_follow_redirects(self):
        with self.assertRaisesRegex(ValueError, 'redirect'):
            source.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example')
        for url in ['http://forgejo.example', 'https://user:password@forgejo.example', 'https://forgejo.example/?token=x']:
            with self.assertRaises(ValueError):
                source.Forgejo({'url': url, 'token_file': '/unused'})


if __name__ == '__main__':
    unittest.main()
