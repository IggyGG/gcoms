"""Durable Forgejo server push receipts, forwarded by a cluster-only worker.

The Forgejo hook needs no network or archive credentials. Its bounded records
remain on the server PVC until this worker verifies their versioned S3 copy.
"""
import argparse
import base64
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import stat
import time

from android_release import canonical, write_json
from android_release_source import PROMOTION
from android_release_store import Archive

MAX_EVENT = 2048
PROJECTS = frozenset(('gcoms', 'dropship', 'gchat', 'drone'))


def decode(raw, now=None):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_EVENT:
        raise ValueError('bounded original server event required')
    value = json.loads(raw)
    fields = {'schema', 'project', 'repository', 'ref', 'commit', 'pushed_at', 'nonce'}
    if not isinstance(value, dict) or set(value) != fields or value['schema'] != 1:
        raise ValueError('unexpected server push event fields')
    project, ref = value['project'], value['ref']
    if (not isinstance(project, str) or project not in PROJECTS
            or value['repository'] != 'ghost-local/' + project
            or not isinstance(ref, str) or len(ref) > 256
            or not re.fullmatch(r'[A-Za-z0-9_./-]+', ref) or '..' in ref):
        raise ValueError('server push repository/reference boundary changed')
    if ref.startswith(PROMOTION):
        valid = project == 'gcoms' and re.fullmatch('[0-9a-f]{64}', ref[len(PROMOTION):])
    else:
        valid = ref == 'refs/heads/main' or ref.startswith('refs/heads/agent/')
    if (not valid or not isinstance(value['commit'], str)
            or not re.fullmatch('[0-9a-f]{40}', value['commit']) or value['commit'] == '0' * 40
            or type(value['pushed_at']) is not int or not 0 < value['pushed_at'] <= (time.time() if now is None else now)
            or not isinstance(value['nonce'], str)
            or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['nonce'])):
        raise ValueError('invalid original server push identity or clock')
    return dict(value, server_event_id=hashlib.sha256(raw).hexdigest())


def receipt(raw, now=None):
    value = decode(raw, now)
    return {'schema': 1, 'kind': 'android-server-push', 'event_sha256': value['server_event_id'],
            'original_b64': base64.b64encode(raw).decode('ascii')}


def restore(value, now=None):
    if (not isinstance(value, dict) or set(value) != {'schema', 'kind', 'event_sha256', 'original_b64'}
            or value['schema'] != 1 or value['kind'] != 'android-server-push'
            or not isinstance(value['original_b64'], str) or len(value['original_b64']) > 4 * MAX_EVENT // 3 + 4):
        raise ValueError('invalid archived server receipt')
    raw = base64.b64decode(value['original_b64'], validate=True)
    event = decode(raw, now)
    if event['server_event_id'] != value['event_sha256']:
        raise ValueError('original server push bytes changed')
    return event


def archive_for(config, client=None):
    settings = dict(config['archive'])
    settings['prefix'] = settings.get('prefix', 'android-release') + '/server-pushes'
    return Archive(settings, client)


def drain(directory, archive, limit=128):
    directory = Path(directory)
    count = 0
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    root = os.open(directory, flags | os.O_DIRECTORY)
    try:
        info = os.fstat(root)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('outbox must be private to the Forgejo server owner')
        with os.scandir(root) as entries:
            names = heapq.nsmallest(limit, (entry.name for entry in entries
                if re.fullmatch('[0-9a-f]{64}\\.json', entry.name)))
        for name in names:
            with os.fdopen(os.open(name, flags, dir_fd=root), 'rb') as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or before.st_mode & 0o077 or before.st_nlink != 1
                        or not 0 < before.st_size <= MAX_EVENT):
                    raise ValueError('outbox event is not a bounded private regular file')
                raw = stream.read(MAX_EVENT + 1)
            value = receipt(raw)
            if name != value['event_sha256'] + '.json':
                raise ValueError('outbox filename differs from original event bytes')
            descriptor = archive.publish_record(value)
            if archive.read_record(descriptor) != value:
                raise ValueError('server event archive readback differs')
            after = os.stat(name, dir_fd=root, follow_symlinks=False)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                    before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                raise ValueError('preserve event changed during archival')
            os.unlink(name, dir_fd=root)
            os.fsync(root)
            count += 1
    finally:
        os.close(root)
    return count


def ingest(config, archive=None):
    archive = archive or archive_for(config)
    prefix = archive.prefix + '/records/'
    cache_root = Path(config['event_directory']).parent / 'server-receipts'
    token, accepted = None, []
    for _ in range(32):
        arguments = {'Bucket': archive.bucket, 'Prefix': prefix, 'MaxKeys': 200}
        if token is not None:
            arguments['ContinuationToken'] = token
        page = archive.client.list_objects_v2(**arguments)
        for row in page.get('Contents', []):
            key = row['Key']
            checksum = key.removeprefix(prefix).removesuffix('.json')
            if key != prefix + checksum + '.json' or not re.fullmatch('[0-9a-f]{64}', checksum):
                raise ValueError('unexpected server receipt object path')
            cached = cache_root / (checksum + '.json')
            if cached.exists() or cached.is_symlink():
                if (cache_root.is_symlink() or cached.is_symlink() or not cached.is_file()
                        or not 0 < cached.stat().st_size <= 4096):
                    raise ValueError('unsafe cached server receipt')
                value = json.loads(cached.read_text())
            else:
                head = archive.client.head_object(Bucket=archive.bucket, Key=key)
                if not 0 < head['ContentLength'] <= 4096:
                    raise ValueError('server receipt exceeds its bound')
                descriptor = archive.descriptor(key, head.get('VersionId'), checksum, head['ContentLength'], True)
                value = archive.read_record(descriptor)
            # Reuse the exact previously verified original bytes. Content-
            # addressed S3 names cannot silently change this event or its clock.
            if hashlib.sha256(canonical(value)).hexdigest() != checksum:
                raise ValueError('cached server receipt SHA-256 changed')
            event = restore(value)
            configured = {r['project']: r['cluster_repository'] for r in config['sources'].values()}
            if configured.get(event['project']) != event['repository']:
                raise ValueError('archived push belongs to an unconfigured repository')
            if not cached.exists():
                write_json(cached, value)
            destination = Path(config['event_directory']) / ('server-' + event['server_event_id'] + '.json')
            if destination.exists():
                if json.loads(destination.read_text()) != event:
                    raise ValueError('original source event changed')
            else:
                write_json(destination, event)
                accepted.append(event)
        if not page.get('IsTruncated'):
            return accepted
        new_token = page.get('NextContinuationToken')
        if not isinstance(new_token, str) or not new_token or new_token == token:
            raise ValueError('server receipt pagination did not advance')
        token = new_token
    raise ValueError('server receipt history requires explicit archival compaction')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--outbox', type=Path, required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    archive = archive_for(config)
    while True:
        try:
            count = drain(args.outbox, archive)
            if count:
                print(json.dumps({'state': 'archived', 'events': count}), flush=True)
        except Exception as error:
            if args.once:
                raise
            print(json.dumps({'state': 'retrying', 'error_type': type(error).__name__}), flush=True)
        if args.once:
            return
        time.sleep(1)


if __name__ == '__main__':
    main()
