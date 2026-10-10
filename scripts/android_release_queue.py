#!/usr/bin/env python3
"""Consume original Forgejo push receipts; no HTTP endpoint or shell dispatch."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import time

from android_release import command, deploy, freeze, git, promotion_manifest, write_json

PROMOTION_PREFIX = 'refs/tags/android-release/'


def events(config):
    selected = {(row['project'], row['ref']) for row in config['sources'].values()}
    result = []
    for path in sorted(Path(config['event_directory']).glob('*.json')):
        if path.is_symlink() or path.stat().st_size > 2048:
            raise ValueError('unsafe push receipt')
        value = json.loads(path.read_text())
        promotion = (value.get('project') == 'gcoms' and isinstance(value.get('ref'), str)
                     and value['ref'].startswith(PROMOTION_PREFIX)
                     and re.fullmatch('[0-9a-f]{64}', value['ref'][len(PROMOTION_PREFIX):]))
        if (((value.get('project'), value.get('ref')) not in selected and not promotion)
                or not re.fullmatch('[0-9a-f]{40}', value.get('commit', ''))
                or type(value.get('pushed_at')) is not int or not 0 < value['pushed_at'] <= time.time()):
            continue
        marker = Path(config['state']) / 'pushes' / path.name
        if not marker.exists():
            result.append((path, value))
    return sorted(result, key=lambda row: (row[1]['pushed_at'], row[0].name))


def dispatch(config, rows):
    state = Path(config['state'])
    # Only undispatched events coalesce. Running releases keep their source
    # manifest, deadline, side effects and original failure receipts.
    path, event = rows[-1]
    for old_path, old in rows[:-1]:
        write_json(state / 'pushes' / old_path.name,
                   {'state': 'superseded_before_dispatch', 'push': old, 'by': path.name})
    marker = state / 'pushes' / path.name
    manifest_path = state / 'push-manifests' / path.name
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
    elif event['ref'].startswith(PROMOTION_PREFIX):
        manifest = promotion_manifest(config, event['ref'][len(PROMOTION_PREFIX):], event['pushed_at'])
        if event['project'] != 'gcoms' or manifest['sources']['gcoms'] != event['commit']:
            raise ValueError('promotion tag differs from prepared SDK source')
        write_json(manifest_path, manifest)
    else:
        matching = [name for name, row in config['sources'].items()
                    if (row['project'], row['ref']) == (event['project'], event['ref'])]
        if any(git(config['sources'][name]['repository'], 'rev-parse', event['ref']).decode().strip()
               != event['commit'] for name in matching):
            write_json(marker, {'state': 'superseded_before_dispatch', 'push': event})
            return {'state': 'superseded_before_dispatch'}
        manifest = freeze(config, event['pushed_at'], {name: event['commit'] for name in matching})
        write_json(manifest_path, manifest)
    receipt = deploy(config, manifest)
    write_json(marker, {'state': receipt['state'], 'release_id': manifest['release_id'], 'push': event})
    write_json(state / 'latest.json', receipt)
    return {'state': receipt['state'], 'release_id': manifest['release_id'],
            'elapsed_seconds': receipt.get('elapsed_seconds')}


def consume(config):
    state = Path(config['state'])
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state / 'queue.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'state': 'another consumer active'}
        rows = events(config)
        if not rows:
            return {'state': 'idle'}
        promotions = [row for row in rows if row[1]['ref'].startswith(PROMOTION_PREFIX)]
        if config.get('require_prepared') and not promotions:
            for path, event in rows:
                write_json(state / 'pushes' / path.name, {'state': 'preparation_requested', 'push': event})
            if config.get('warm_unit'):
                command(['systemctl', '--user', 'start', '--no-block', config['warm_unit']],
                        timeout=5, log=state / 'warm-preemption.log')
            return {'state': 'preparation_requested', 'pushes': len(rows)}
        # Live pushes take priority over speculative preparation. Stop only
        # this lane's warming unit; the original push clock keeps running.
        if config.get('warm_unit'):
            command(['systemctl', '--user', 'stop', config['warm_unit']], timeout=15,
                    log=state / 'warm-preemption.log')
        try:
            chosen = [promotions[0]] if promotions else rows
            try:
                return dispatch(config, chosen)
            except Exception as error:
                path, event = chosen[-1]
                failed = {'state': 'failed', 'failure_stage': 'promotion_validation',
                          'failure_type': type(error).__name__, 'push': event,
                          'pushed_at': event['pushed_at'], 'elapsed_seconds': time.time() - event['pushed_at']}
                write_json(state / 'pushes' / path.name, failed)
                write_json(state / 'latest.json', failed)
                return failed
        finally:
            # Resume preparation immediately for the next push. A preflight
            # failure must not leave caches cold until the next twelve-hour tick.
            # This asynchronous job cannot turn the failed release into a pass.
            if config.get('warm_unit'):
                command(['systemctl', '--user', 'start', '--no-block', config['warm_unit']],
                        timeout=5, log=state / 'warm-preemption.log')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(consume(json.loads(args.config.read_text()))))


if __name__ == '__main__':
    main()
