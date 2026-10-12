"""Cold state recovery preserves native receipts and original failed clocks."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release as release
import android_release_catalogue as catalogue
from android_release_kubernetes_test import API
from android_release_store_test import S3
from android_release_store import Archive, ENDPOINT


class Publication(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {'state': str(self.root / 'state'), 'kubernetes': {'namespace': 'ghost'},
            'archive': {'endpoint': ENDPOINT, 'region': 'fsn1', 'bucket': 'android-fixture',
                        'catalogue': 'android-release-objects'}}
        self.api = API()
        self.s3 = S3()
        self.archive = Archive(self.config['archive'], self.s3)
        self.catalogue = catalogue.Catalogue(self.config, self.api, self.archive)

    def artifact(self):
        root = self.root / 'original'
        root.mkdir()
        (root / 'worker.so').write_bytes(b'original native bytes')
        receipt = {'component': 'worker', 'input_sha256': 'a' * 64,
                   'sources': {'drone': 'b' * 40}, 'files': {'worker.so': release.digest(root / 'worker.so')}}
        release.write_json(root / 'receipt.json', receipt)
        self.catalogue.artifact('worker', 'a' * 64, root)
        return receipt

    def test_release_cache_hydrates_exact_original_receipt_from_cluster_catalogue(self):
        original = self.artifact()
        with patch.object(catalogue, 'Catalogue', return_value=self.catalogue):
            self.assertEqual(release.cached_artifact(self.config, 'worker', 'a' * 64), original)
        self.assertEqual((self.root / ('state/artifacts/worker/' + 'a' * 64) / 'worker.so').read_bytes(),
                         b'original native bytes')

    def test_different_artifact_cannot_rebind_a_published_input(self):
        self.artifact()
        root = self.root / 'original'
        (root / 'worker.so').write_bytes(b'changed native bytes')
        receipt = json.loads((root / 'receipt.json').read_text())
        receipt['files']['worker.so'] = release.digest(root / 'worker.so')
        release.write_json(root / 'receipt.json', receipt)
        before = self.catalogue.lookup('artifacts', 'worker/' + 'a' * 64)
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.catalogue.artifact('worker', 'a' * 64, root)
        self.assertEqual(self.catalogue.lookup('artifacts', 'worker/' + 'a' * 64), before)

    def test_corrupt_existing_cache_is_preserved_and_rejected(self):
        self.artifact()
        with patch.object(catalogue, 'Catalogue', return_value=self.catalogue):
            release.cached_artifact(self.config, 'worker', 'a' * 64)
            payload = self.root / ('state/artifacts/worker/' + 'a' * 64) / 'worker.so'
            payload.write_bytes(b'corrupt retained evidence')
            with self.assertRaisesRegex(ValueError, 'bytes changed'):
                release.cached_artifact(self.config, 'worker', 'a' * 64)
            self.assertEqual(payload.read_bytes(), b'corrupt retained evidence')

    def test_prepared_receipt_recovery_cannot_change_its_identity(self):
        value = {'schema': 1, 'kind': 'android-prepared-release', 'sources': {'gcoms': 'a' * 40}}
        value['prepared_id'] = hashlib.sha256(release.canonical(value)).hexdigest()
        self.catalogue.prepared(value)
        destination = self.root / 'cold/prepared.json'
        self.assertTrue(self.catalogue.hydrate_prepared(value['prepared_id'], destination))
        self.assertEqual(json.loads(destination.read_text()), value)
        with self.assertRaisesRegex(ValueError, 'preserve existing'):
            self.catalogue.hydrate_prepared(value['prepared_id'], destination)
        value['sources']['gcoms'] = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'identifier differs'):
            self.catalogue.prepared(value)

    def failed_run(self):
        manifest = {'schema': 1, 'pushed_at': 100, 'sources': {'gcoms': 'a' * 40}}
        manifest['release_id'] = hashlib.sha256(release.canonical(manifest)).hexdigest()
        receipt = {'release_id': manifest['release_id'], 'pushed_at': 100, 'state': 'failed',
                   'elapsed_seconds': 601, 'failure_stage': 'readiness'}
        root = self.root / 'failed'
        release.write_json(root / 'manifest.json', manifest)
        release.write_json(root / 'receipt.json', receipt)
        self.catalogue.run(root)
        return manifest, receipt

    def test_failure_restores_original_terminal_receipt_without_new_clock(self):
        manifest, receipt = self.failed_run()
        cold = self.root / 'cold/run'
        self.assertTrue(self.catalogue.hydrate_run(manifest['release_id'], cold))
        self.assertEqual(json.loads((cold / 'receipt.json').read_text()), receipt)
        self.assertEqual(json.loads((cold / 'manifest.json').read_text()), manifest)
        self.assertTrue(self.catalogue.hydrate_run(manifest['release_id'], cold))
        altered = dict(receipt, pushed_at=101)
        release.write_json(cold / 'receipt.json', altered)
        with self.assertRaisesRegex(ValueError, 'preserve differing'):
            self.catalogue.hydrate_run(manifest['release_id'], cold)

    def test_failure_cannot_be_replaced_by_success_or_unbound_evidence(self):
        manifest, receipt = self.failed_run()
        root = self.root / 'failed'
        release.write_json(root / 'receipt.json', dict(receipt, state='live'))
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.catalogue.run(root)
        release.write_json(root / 'receipt.json', dict(receipt, pushed_at=101))
        with self.assertRaisesRegex(ValueError, 'original terminal'):
            self.catalogue.run(root)

    def test_remote_evidence_cannot_inject_a_path(self):
        manifest, receipt = self.failed_run()
        bad = self.archive.publish_record({'schema': 1, 'manifest': manifest, 'receipt': receipt,
                                          '../escaped.json': {'bad': True}})
        with patch.object(self.catalogue, 'lookup', return_value=bad):
            with self.assertRaisesRegex(ValueError, 'evidence path'):
                self.catalogue.hydrate_run(manifest['release_id'], self.root / 'cold')
        self.assertFalse((self.root / 'escaped.json').exists())

    def test_catalogue_never_overwrites_another_application(self):
        self.api.create('configmap', {'metadata': {'name': 'android-release-objects', 'labels': {}},
                                      'data': {'catalogue.json': '{}'}})
        with self.assertRaisesRegex(ValueError, 'another application'):
            self.catalogue.lookup('artifacts', 'worker/' + 'a' * 64)

    def test_checkpoint_pointer_advances_only_after_verified_object_write(self):
        first = self.archive.publish_record({'original_cursor': 10})
        second = self.archive.publish_record({'original_cursor': 11})
        self.catalogue.bind('checkpoints', 'coordinator', first, replace=True)
        self.catalogue.bind('checkpoints', 'coordinator', second, replace=True)
        self.assertEqual(self.catalogue.lookup('checkpoints', 'coordinator'), second)
        with self.assertRaisesRegex(ValueError, 'only the coordinator'):
            self.catalogue.bind('runs', 'a' * 64, first, replace=True)

    def test_full_catalogue_preserves_existing_entries(self):
        self.artifact()
        before = self.catalogue.read()[1]
        descriptor = self.archive.publish_record({'another': 'value'})
        with patch.object(catalogue, 'MAX_CATALOGUE', len(release.canonical(before))):
            with self.assertRaisesRegex(ValueError, 'capacity reached'):
                self.catalogue.bind('prepared', 'b' * 64, descriptor)
        self.assertEqual(self.catalogue.read()[1], before)


if __name__ == '__main__':
    unittest.main()
