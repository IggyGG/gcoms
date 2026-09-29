#!/usr/bin/env python3
"""Run trusted local validation commands without losing independent failures.

Manifests contain argv arrays, never shell text or secrets. Run CPU-heavy suites
on a cluster worker or through workstation-batch. This runner records component
results; it does not turn them into installed-app or production qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    names = subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root)
    files = {}
    for raw in sorted(set(names.split(b'\0')) - {b''}):
        name = os.fsdecode(raw)
        path = root / name
        if path.is_symlink():
            files[name] = {'symlink': os.readlink(path)}
        else:
            files[name] = digest(path) if path.is_file() else None
    return {'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root,
                                               text=True).strip(), 'files': files}


def validate(manifest):
    cases = manifest['cases']
    if not isinstance(cases, list) or not 1 <= len(cases) <= 128:
        raise ValueError('suite must contain 1..128 cases')
    seen = set()
    for case in cases:
        name = case['id']
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,79}', name) or name in seen:
            raise ValueError('invalid or duplicate case ID')
        for key in ('command', 'cleanup'):
            if key == 'cleanup' and key not in case:
                continue
            argv = case[key]
            if not isinstance(argv, list) or not argv or not all(
                    isinstance(arg, str) and arg and '\0' not in arg for arg in argv):
                raise ValueError('commands must be nonempty argv arrays')
        timeout = case['timeout_seconds']
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 21600:
            raise ValueError('invalid timeout')
        dependencies = case.get('requires', [])
        if not isinstance(dependencies, list) or not all(isinstance(d, str) and d in seen for d in dependencies):
            raise ValueError('dependencies must name earlier cases')
        requirements = case['requirements']
        if not isinstance(requirements, list) or not requirements or not all(
                isinstance(r, str) and re.fullmatch(r'R(?:0[1-9]|1[0-2])', r) for r in requirements):
            raise ValueError('invalid requirement IDs')
        seen.add(name)
    return cases


def execute(argv, cwd, timeout, log):
    start = time.monotonic()
    result = {'command': argv, 'timeout_seconds': timeout}
    with log.open('xb') as stream:
        try:
            child = subprocess.Popen(argv, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, start_new_session=True)
        except OSError as error:
            result.update(status='error', error=str(error), exit_code=None)
        else:
            try:
                code = child.wait(timeout=timeout)
                result.update(status='passed' if code == 0 else 'failed', exit_code=code)
            except subprocess.TimeoutExpired:
                result.update(status='timeout', exit_code=None)
            except KeyboardInterrupt:
                result.update(status='interrupted', exit_code=None)
            finally:
                # Every case owns its process group. Reap descendants even if
                # the leader exited before a fixture daemon or timed out.
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
    result.update(elapsed_seconds=time.monotonic() - start,
                  log=log.name, log_sha256=digest(log))
    return result


def run_suite(manifest, root, output):
    if os.name != 'posix':
        raise ValueError('suite process-group ownership requires a POSIX worker')
    cases = validate(manifest)
    root = root.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = snapshot(root)
    (output / 'before.json').write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    results = {}
    report = {'scope': 'command_suite_only', 'cases': results, 'passed': False}
    try:
        for case in cases:
            name = case['id']
            dependencies = [d for d in case.get('requires', []) if results[d]['status'] != 'passed']
            if dependencies:
                result = {'status': 'blocked', 'blocked_by': dependencies}
            else:
                case_output = output / name
                case_output.mkdir()
                result = execute(case['command'], root, case['timeout_seconds'], case_output / 'command.log')
                result['log'] = name + '/command.log'
                if 'cleanup' in case:
                    cleanup = execute(case['cleanup'], root, 30, case_output / 'cleanup.log')
                    cleanup['log'] = name + '/cleanup.log'
                    result['cleanup'] = cleanup
                    if cleanup['status'] != 'passed':
                        result['command_status'] = result['status']
                        result['status'] = 'cleanup_failed'
            result['requirements'] = case['requirements']
            results[name] = result
            (output / 'progress.json').write_text(json.dumps(report, indent=2) + '\n')
            if result.get('status') == 'interrupted' or result.get('command_status') == 'interrupted':
                break
    finally:
        after = snapshot(root)
        (output / 'after.json').write_text(json.dumps(after, sort_keys=True, indent=2) + '\n')
        report['source_unchanged'] = before == after
        report['passed'] = before == after and len(results) == len(cases) and all(
            r['status'] == 'passed' for r in results.values())
        report['bindings'] = {name: digest(output / name) for name in ('before.json', 'after.json', 'manifest.json')}
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    report = run_suite(json.loads(args.manifest.read_text()), args.root, args.output.resolve())
    print(json.dumps({'passed': report['passed'], 'cases': {k: v['status'] for k, v in report['cases'].items()},
                      'summary': str(args.output / 'summary.json')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
