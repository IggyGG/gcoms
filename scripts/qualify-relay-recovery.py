#!/usr/bin/env python3
"""Run the unchanged isolated relay gate without signing or deploying a release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def provider(environment):
    result = {'kind': 'github-actions-diagnostic',
              'repository': environment.get('GITHUB_REPOSITORY'),
              'run_id': environment.get('GITHUB_RUN_ID'),
              'workflow_commit': environment.get('GITHUB_SHA')}
    attempt = environment.get('GITHUB_RUN_ATTEMPT', '')
    if (result['repository'] != 'IggyGG/gcoms'
            or not re.fullmatch('[1-9][0-9]*', result['run_id'] or '')
            or not re.fullmatch('[1-9][0-9]*', attempt)
            or not re.fullmatch('[0-9a-f]{40}', result['workflow_commit'] or '')):
        raise ValueError('diagnostic requires its actual GitHub workflow identity')
    result['run_attempt'] = int(attempt)
    return result


def run(gchat, output, work, target, origin):
    gchat, output, work, target = (Path(p).resolve() for p in (gchat, output, work, target))
    sys.path.insert(0, str(gchat / 'scripts'))
    from relay_load_run import execute, retain_journey
    from release_evidence import digest, source_identity
    from release_relay_load import verify

    repositories = {'gcoms': ROOT, 'gchat': gchat}
    sources = {name: source_identity(path) for name, path in repositories.items()}
    if sources['gcoms']['commit'] != origin['workflow_commit']:
        raise ValueError('diagnostic workflow and GComs source must be the same commit')
    for path in (output, work, target):
        if any(path.is_relative_to(source) for source in repositories.values()):
            raise ValueError('diagnostic output must stay outside both source checkouts')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {'release_id': 'diagnostic-' + hashlib.sha256(
        json.dumps(sources, sort_keys=True).encode()).hexdigest(), 'sources': sources}
    report = {'schema': 1, 'kind': 'relay_load', **manifest, 'provider': origin,
              'passed': False, 'source_unchanged': False, 'release_qualified': False,
              'strict_verifier_passed': False,
              'scope': 'isolated runtime diagnostic; signing and deployment remain separately gated',
              'started_at': int(time.time()), 'evidence': {}}
    build = work / 'build'
    try:
        execute(['python3', ROOT / 'scripts/build-fleet-files.py', '--gchat', gchat,
                 '--output', build, '--target-dir', target, '--fetch'],
                ROOT, output / 'build.log', 3600)
        for mode, name, timeout in [('relay-preflight', 'preflight', 330),
                                    ('relay-load', 'load', 4530)]:
            command = ['python3', ROOT / 'scripts/gchat-turnover.py', '--build', build,
                       '--fixture-host', build / 'bin/turnover_daemon', '--mode', mode,
                       '--out', work / name]
            if mode == 'relay-load':
                command += ['--load-seconds', '1800', '--load-relay-circuits', '2048',
                            '--load-relay-connections', '4096']
            try:
                execute(command, ROOT, output / (name + '.log'), timeout)
            finally:
                retain_journey(work / name, output / name)
        report['passed'] = True
    finally:
        if (build / 'build.json').is_file():
            shutil.copyfile(build / 'build.json', output / 'build.json')
        try:
            report['source_unchanged'] = all(source_identity(path) == sources[name]
                                             for name, path in repositories.items())
        except (ValueError, OSError, subprocess.CalledProcessError):
            report['source_check_failed'] = True
        report['passed'] = report['passed'] and report['source_unchanged']
        report['completed_at'] = int(time.time())
        report['evidence'] = {p.relative_to(output).as_posix(): digest(p)
                              for p in sorted(output.rglob('*')) if p.is_file()}
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        verify(output, manifest, origin)
        report['strict_verifier_passed'] = True
    finally:
        report['passed'] = report['passed'] and report['strict_verifier_passed']
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('gchat', 'output', 'work', 'target-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    run(args.gchat, args.output, args.work, args.target_dir, provider(os.environ))
