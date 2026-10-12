"""Version-pinned FSN1 objects for Android artifacts and original evidence.

Publication ownership belongs to the release coordinator. This module only
writes content-addressed objects: an S3 overwrite is never used as a lock or
as a mutable latest-release pointer.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile

from android_release import canonical, digest

ENDPOINT = 'https://fsn1.your-objectstorage.com'
MAX_RECORD = 2 * 1024 ** 2
MAX_FILE = 1024 ** 3
MAX_ARTIFACT = 4 * 1024 ** 3
MAX_FILES = 2048
BLOCK = 1024 ** 2


def sha256(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('SHA-256 identity required')
    return value


def relative_name(value):
    if (not isinstance(value, str) or not value or '\\' in value or '\x00' in value
            or PurePosixPath(value).is_absolute()
            or any(part in ('', '.', '..') for part in value.split('/'))
            or len(value.encode()) > 1024):
        raise ValueError('safe relative artifact filename required')
    return value


def regular_file(root, name):
    relative_name(name)
    path = root / name
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError('artifact symlinks are forbidden')
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('artifact must be a regular file inside its root')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        raise ValueError('artifact file type or size exceeds its bound')
    return path


def missing(error):
    return getattr(error, 'response', {}).get('Error', {}).get('Code') in ('404', 'NoSuchKey')


class Archive:
    def __init__(self, config, client=None):
        if config.get('endpoint') != ENDPOINT or config.get('region') != 'fsn1':
            raise ValueError('Android archives require verified FSN1 S3')
        self.bucket = config['bucket']
        self.prefix = relative_name(config.get('prefix', 'android-release'))
        if not re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', self.bucket):
            raise ValueError('invalid archive bucket')
        if client is None:
            import boto3
            from botocore.config import Config
            credentials = json.loads(Path(config['credentials_file']).read_text())
            client = boto3.client('s3', endpoint_url=ENDPOINT, region_name='fsn1',
                aws_access_key_id=credentials['access_key'],
                aws_secret_access_key=credentials['secret_key'],
                config=Config(signature_version='s3v4', connect_timeout=5, read_timeout=30,
                    retries={'max_attempts': 2}, s3={'addressing_style': 'path'},
                    request_checksum_calculation='when_required',
                    response_checksum_validation='when_required'))
        self.client = client
        if client.get_bucket_location(Bucket=self.bucket).get('LocationConstraint') != 'fsn1':
            raise ValueError('archive bucket is outside FSN1')
        if client.get_bucket_versioning(Bucket=self.bucket).get('Status') != 'Enabled':
            raise ValueError('archive versioning must be enabled')

    def key(self, checksum, record=False):
        return self.prefix + ('/records/' if record else '/blobs/') + sha256(checksum) + ('.json' if record else '')

    def descriptor(self, key, version, checksum, size, record=False):
        limit = MAX_RECORD if record else MAX_FILE
        if (key != self.key(checksum, record) or not isinstance(version, str)
                or not version or version == 'null' or len(version) > 1024
                or type(size) is not int or not 0 <= size <= limit):
            raise ValueError('invalid version-pinned archive object')
        return {'key': key, 'version': version, 'sha256': checksum, 'bytes': size}

    def read(self, descriptor, destination=None, record=False):
        item = self.descriptor(descriptor['key'], descriptor['version'],
                               descriptor['sha256'], descriptor['bytes'], record)
        response = self.client.get_object(Bucket=self.bucket, Key=item['key'], VersionId=item['version'])
        body = response['Body']
        try:
            if (response.get('VersionId') != item['version']
                    or response.get('ContentLength') != item['bytes']
                    or response.get('Metadata', {}).get('sha256') != item['sha256']):
                raise ValueError('archive object version/length/digest metadata changed')
            hasher, count, pieces = hashlib.sha256(), 0, []
            while True:
                block = body.read(min(BLOCK, item['bytes'] - count + 1))
                if not block:
                    break
                count += len(block)
                if count > item['bytes']:
                    raise ValueError('archive object exceeds its declared length')
                hasher.update(block)
                if destination is not None:
                    destination.write(block)
                elif record:
                    pieces.append(block)
            if count != item['bytes'] or hasher.hexdigest() != item['sha256']:
                raise ValueError('archive object bytes failed SHA-256 verification')
            return b''.join(pieces) if record and destination is None else None
        finally:
            body.close()

    def put(self, source, checksum, size, record=False):
        key = self.key(checksum, record)
        self.descriptor(key, 'unpublished', checksum, size, record)
        try:
            head = self.client.head_object(Bucket=self.bucket, Key=key)
        except Exception as error:
            if not missing(error):
                raise
            head = None
        if head is None:
            # All writers for a key must supply the same content hash. There
            # is no mutable pointer here and no conditional-PUT assumption.
            result = self.client.put_object(Bucket=self.bucket, Key=key, Body=source,
                ContentLength=size, Metadata={'sha256': sha256(checksum)},
                ContentType='application/json' if record else 'application/octet-stream')
            version = result.get('VersionId')
        else:
            version = head.get('VersionId')
        descriptor = self.descriptor(key, version, checksum, size, record)
        self.read(descriptor, record=record)  # Verify bytes before publishing a reference.
        return descriptor

    def publish_record(self, value):
        data = canonical(value)
        if len(data) > MAX_RECORD:
            raise ValueError('archive record exceeds its bound')
        return self.put(data, hashlib.sha256(data).hexdigest(), len(data), record=True)

    def read_record(self, descriptor):
        return json.loads(self.read(descriptor, record=True))

    def publish_directory(self, directory, component, input_sha256):
        root = Path(directory).resolve()
        sha256(input_sha256)
        marker = regular_file(root, 'receipt.json')
        if marker.stat().st_size > MAX_RECORD:
            raise ValueError('artifact receipt exceeds its bound')
        receipt = json.loads(marker.read_text())
        if receipt.get('component') != component or receipt.get('input_sha256') != input_sha256:
            raise ValueError('artifact receipt source/input binding changed')
        expected = receipt.get('files')
        if (not isinstance(expected, dict) or not expected or len(expected) >= MAX_FILES
                or 'receipt.json' in expected):
            raise ValueError('bounded artifact file inventory required')
        files, total = {}, 0
        for name, checksum in sorted({**expected, 'receipt.json': digest(marker)}.items()):
            path = regular_file(root, name)
            checksum = sha256(checksum)
            size = path.stat().st_size
            total += size
            if total > MAX_ARTIFACT or digest(path) != checksum:
                raise ValueError('artifact bytes differ from receipt or exceed the size bound')
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o7000:
                raise ValueError('special artifact mode is forbidden')
            with path.open('rb') as stream:
                item = self.put(stream, checksum, size)
            if digest(path) != checksum:
                raise ValueError('artifact changed during archive publication')
            files[name] = dict(item, mode=mode)
        return self.publish_record({'schema': 1, 'kind': 'android-artifact',
            'component': component, 'input_sha256': input_sha256, 'files': files})

    def restore_directory(self, descriptor, destination, component, input_sha256):
        value = self.read_record(descriptor)
        sha256(input_sha256)
        if (value.get('schema') != 1 or value.get('kind') != 'android-artifact'
                or value.get('component') != component or value.get('input_sha256') != input_sha256):
            raise ValueError('archived artifact source/input binding differs')
        files = value.get('files')
        if not isinstance(files, dict) or not 0 < len(files) <= MAX_FILES or 'receipt.json' not in files:
            raise ValueError('bounded archived artifact inventory required')
        total = 0
        for name, item in files.items():
            relative_name(name)
            self.descriptor(item['key'], item['version'], item['sha256'], item['bytes'])
            total += item['bytes']
            if type(item.get('mode')) is not int or item['mode'] < 0 or item['mode'] & ~0o777:
                raise ValueError('unsafe artifact mode')
        if total > MAX_ARTIFACT or files['receipt.json']['bytes'] > MAX_RECORD:
            raise ValueError('archived artifact exceeds its size bound')
        destination = Path(destination)
        if destination.exists() or destination.is_symlink():
            raise ValueError('preserve existing artifact destination')
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Staging belongs to the destination volume, never a workstation /tmp.
        staging = Path(tempfile.mkdtemp(prefix='.hydrate-', dir=destination.parent))
        try:
            for name, item in files.items():
                path = staging / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with path.open('xb') as stream:
                    self.read(item, destination=stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                path.chmod(item['mode'])
            receipt = json.loads((staging / 'receipt.json').read_text())
            expected = {name: item['sha256'] for name, item in files.items() if name != 'receipt.json'}
            if (receipt.get('component') != component or receipt.get('input_sha256') != input_sha256
                    or receipt.get('files') != expected):
                raise ValueError('restored receipt differs from archived file inventory')
            # The coordinator's artifact lease owns this destination. Never
            # merge a partial download into an existing cache tree.
            if destination.exists() or destination.is_symlink():
                raise ValueError('artifact destination appeared during hydration')
            os.rename(staging, destination)
            descriptor_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor_fd)
            finally:
                os.close(descriptor_fd)
            return receipt
        finally:
            if staging.exists():
                shutil.rmtree(staging)
