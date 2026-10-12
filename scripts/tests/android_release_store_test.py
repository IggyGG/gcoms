"""Byte, version and failure controls for the FSN artifact store."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_release_store as store


class Absent(Exception):
    response = {'Error': {'Code': 'NoSuchKey'}}


class S3:
    def __init__(self):
        self.objects = {}
        self.sequence = 0
        self.corrupt = None
        self.versioning = 'Enabled'
        self.location = 'fsn1'

    def get_bucket_location(self, **kwargs):
        return {'LocationConstraint': self.location}

    def get_bucket_versioning(self, **kwargs):
        return {'Status': self.versioning}

    def head_object(self, Key, **kwargs):
        if Key not in self.objects:
            raise Absent()
        return self.metadata(self.objects[Key][-1])

    def metadata(self, value):
        version, data, metadata = value
        return {'VersionId': version, 'ContentLength': len(data), 'Metadata': metadata}

    def put_object(self, Key, Body, Metadata, **kwargs):
        self.sequence += 1
        version = str(self.sequence)
        data = Body if isinstance(Body, bytes) else Body.read()
        self.objects.setdefault(Key, []).append((version, data, dict(Metadata)))
        return {'VersionId': version}

    def get_object(self, Key, VersionId, **kwargs):
        versions = self.objects.get(Key, [])
        value = next((v for v in versions if v[0] == VersionId), None)
        if value is None:
            raise Absent()
        data = value[1]
        if Key == self.corrupt:
            data = bytes([data[0] ^ 1]) + data[1:]
        return dict(self.metadata(value), Body=io.BytesIO(data))


class Archives(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.client = S3()
        self.config = {'endpoint': store.ENDPOINT, 'region': 'fsn1',
                       'bucket': 'private-android-artifacts', 'prefix': 'android-release'}
        self.archive = store.Archive(self.config, self.client)
        self.source = self.root / 'source'
        (self.source / 'x86_64').mkdir(parents=True)
        self.payload = self.source / 'x86_64/worker.so'
        self.payload.write_bytes(b'actual unchanged worker bytes\x00' * 300)
        self.payload.chmod(0o755)
        self.input = '1' * 64
        self.receipt = {'component': 'worker', 'input_sha256': self.input,
                        'sources': {'drone': '2' * 40},
                        'files': {'x86_64/worker.so': store.digest(self.payload)}}
        (self.source / 'receipt.json').write_text(json.dumps(self.receipt))

    def publish(self):
        return self.archive.publish_directory(self.source, 'worker', self.input)

    def test_restore_from_empty_cache_retains_bytes_modes_and_original_receipt(self):
        descriptor = self.publish()
        destination = self.root / 'empty-cache/worker'
        value = self.archive.restore_directory(descriptor, destination, 'worker', self.input)
        self.assertEqual(value, self.receipt)
        self.assertEqual((destination / 'receipt.json').read_bytes(), (self.source / 'receipt.json').read_bytes())
        self.assertEqual((destination / 'x86_64/worker.so').read_bytes(), self.payload.read_bytes())
        self.assertEqual((destination / 'x86_64/worker.so').stat().st_mode & 0o777, 0o755)
        self.assertFalse(list(destination.parent.glob('.hydrate-*')))

    def test_same_artifact_reuses_verified_objects(self):
        first = self.publish()
        before = self.client.sequence
        self.assertEqual(self.publish(), first)
        self.assertEqual(self.client.sequence, before)

    def test_pinned_version_survives_later_object_replacement(self):
        descriptor = self.publish()
        value = self.archive.read_record(descriptor)
        blob = value['files']['x86_64/worker.so']
        self.client.put_object(Key=blob['key'], Body=b'new invalid bytes', Metadata={'sha256': 'f' * 64})
        destination = self.root / 'restored'
        self.archive.restore_directory(descriptor, destination, 'worker', self.input)
        self.assertEqual((destination / 'x86_64/worker.so').read_bytes(), self.payload.read_bytes())

    def test_corrupt_download_does_not_publish_partial_cache(self):
        descriptor = self.publish()
        value = self.archive.read_record(descriptor)
        self.client.corrupt = value['files']['x86_64/worker.so']['key']
        destination = self.root / 'restored'
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.archive.restore_directory(descriptor, destination, 'worker', self.input)
        self.assertFalse(destination.exists())
        self.assertFalse(list(destination.parent.glob('.hydrate-*')))
        self.assertEqual(store.digest(self.payload), self.receipt['files']['x86_64/worker.so'])

    def test_existing_cache_is_preserved(self):
        descriptor = self.publish()
        for destination in (self.source, self.root / 'link'):
            if destination != self.source:
                destination.symlink_to(self.source, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'preserve existing'):
                self.archive.restore_directory(descriptor, destination, 'worker', self.input)
        self.assertEqual(store.digest(self.payload), self.receipt['files']['x86_64/worker.so'])

    def test_symlink_and_parent_escape_rejected_before_upload(self):
        self.payload.unlink()
        outside = self.root / 'outside'
        outside.write_bytes(b'private')
        self.payload.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            self.publish()
        for name in ('../outside', '/absolute', 'x/../outside', 'x//y', 'x\\y', './file'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                store.relative_name(name)

    def test_wrong_input_or_component_cannot_hydrate(self):
        descriptor = self.publish()
        for component, key in [('sdk', self.input), ('worker', '3' * 64)]:
            with self.assertRaisesRegex(ValueError, 'binding differs'):
                self.archive.restore_directory(descriptor, self.root / 'restored', component, key)

    def test_manifest_path_mode_and_receipt_substitution_are_rejected(self):
        original = self.archive.read_record(self.publish())
        for mutation in ('path', 'mode', 'receipt'):
            value = copy.deepcopy(original)
            if mutation == 'path':
                value['files']['../escape'] = value['files'].pop('x86_64/worker.so')
            elif mutation == 'mode':
                value['files']['x86_64/worker.so']['mode'] = 0o4755
            else:
                value['files']['changed-name'] = value['files'].pop('x86_64/worker.so')
            descriptor = self.archive.publish_record(value)
            destination = self.root / mutation
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.archive.restore_directory(descriptor, destination, 'worker', self.input)
            self.assertFalse(destination.exists())

    def test_location_versioning_and_record_size_are_enforced(self):
        self.client.versioning = 'Suspended'
        with self.assertRaisesRegex(ValueError, 'versioning'):
            store.Archive(self.config, self.client)
        self.client.versioning = 'Enabled'
        self.client.location = 'hel1'
        with self.assertRaisesRegex(ValueError, 'outside FSN1'):
            store.Archive(self.config, self.client)
        with self.assertRaisesRegex(ValueError, 'exceeds its bound'):
            self.archive.publish_record({'data': 'x' * store.MAX_RECORD})

    def test_original_failure_receipt_roundtrips_without_new_clock(self):
        receipt = {'state': 'failed', 'pushed_at': 1700000000,
                   'elapsed_seconds': 601.25, 'failure_stage': 'readiness'}
        descriptor = self.archive.publish_record(receipt)
        self.assertEqual(self.archive.read_record(descriptor), receipt)


if __name__ == '__main__':
    unittest.main()
