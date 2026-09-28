#!/usr/bin/env python3
"""Native Windows pipe authentication regression and exact original control."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('requires disposable native Windows CI worker')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'crates/sdk/src/local.rs'
    original = source.read_bytes()
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')

    def snapshot():
        return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in files if name}

    before = snapshot()
    report = {'passed': False, 'source_commit': subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'checks': []}
    cargo = ['cargo', '+1.98.0']
    base = ['--locked', '-p', 'gcoms-sdk', '--no-default-features', '--features', 'ipc']

    def check(name, command, expected=0, assertion=None):
        start = time.monotonic()
        path = output / (name + '.log')
        with path.open('wb') as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=1200, check=False)
        passed = result.returncode == expected
        if assertion is not None:
            passed = passed and assertion in path.read_text(errors='replace')
        report['checks'].append({'name': name, 'exit_code': result.returncode, 'passed': passed,
                                 'seconds': time.monotonic() - start,
                                 'log_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        if not passed:
            raise RuntimeError('check failed: ' + name)

    try:
        check('format', cargo + ['fmt', '--all', '--', '--check'])
        check('regressions', cargo + ['test'] + base + ['--test', 'local_windows', '--', '--test-threads=1', '--nocapture'])
        check('sdk-ipc', cargo + ['test'] + base + ['--lib', '--', '--test-threads=1'])
        check('clippy', cargo + ['clippy'] + base + ['--all-targets', '--', '-D', 'warnings'])
        source.write_bytes(subprocess.check_output(
            ['git', 'show', 'beb0df9354f1d584e4c8d969185471417657502c:crates/sdk/src/local.rs'], cwd=ROOT))
        check('cancelled-accept-negative-control', cargo + ['test'] + base + ['--test', 'local_windows',
              'cancelled_accept_preserves_the_same_client_and_first_byte', '--', '--exact', '--nocapture'],
              expected=101, assertion='cancelled accept must preserve the connected client')
        source.write_bytes(subprocess.check_output(
            ['git', 'show', 'd82e0b0de1dee15be1074a8f2fa68b2ac1ffe654:crates/sdk/src/local.rs'], cwd=ROOT))
        check('original-negative-control', cargo + ['test'] + base + ['--test', 'local_windows',
              'silent_probe_is_not_admitted_and_cancellation_keeps_listener_usable', '--', '--exact', '--nocapture'],
              expected=101, assertion='silent connection must not be admitted or terminate the listener')
        source.write_bytes(original)
        check('sdk-all-features', cargo + ['test', '--locked', '-p', 'gcoms-sdk', '--all-features',
              '--lib', '--', '--test-threads=1'])
        check('clippy-all-features', cargo + ['clippy', '--locked', '-p', 'gcoms-sdk', '--all-features',
              '--all-targets', '--', '-D', 'warnings'])
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
    finally:
        source.write_bytes(original)
        after = snapshot()
        report['source_unchanged'] = before == after
        report['passed'] = report['passed'] and report['source_unchanged']
        (output / 'before.json').write_text(json.dumps(before, sort_keys=True))
        (output / 'after.json').write_text(json.dumps(after, sort_keys=True))
        (output / 'summary.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
