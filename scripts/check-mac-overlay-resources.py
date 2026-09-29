#!/usr/bin/env python3
"""Compare one unchanged 24-node fixture with explicit disposable host resources.

Never run on a personal Mac or deployed relay. This diagnoses co-location limits,
not a production runtime fix, platform release pass, or latency qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Darwin' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('requires disposable GitHub Mac worker')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'crates/node/tests/node_overlay.rs'
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (8192, hard))
    key = 'net.inet.ip.portrange.first'
    old = subprocess.check_output(['sysctl', '-n', key], text=True).strip()
    report = {'diagnostic_only': True, 'passed': False, 'source_sha256': source_hash,
              'original_nofile': [soft, hard], 'original_ephemeral_first': old, 'checks': []}
    try:
        with (output / 'compile.log').open('wb') as log:
            subprocess.run(['cargo', '+1.98.0', 'test', '--locked', '-p', 'gcoms-node',
                            '--test', 'node_overlay', '--all-features', '--no-run', '--message-format=json'],
                           cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=900)
        artifacts = []
        for line in (output / 'compile.log').read_text().splitlines():
            try:
                row = json.loads(line)
                if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'node_overlay' and row.get('executable'):
                    artifacts.append(Path(row['executable']))
            except ValueError:
                pass
        if len(artifacts) != 1:
            raise RuntimeError('ambiguous overlay executable')
        binary = artifacts[0]
        report['binary_sha256'] = hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest()
        for label, first in [('baseline', int(old)), ('expanded', 10240)]:
            if label == 'expanded':
                subprocess.run(['sudo', 'sysctl', '-w', key + '=' + str(first)], check=True)
            tmp = output / (label + '-tmp')
            tmp.mkdir(mode=0o700)
            started = time.monotonic()
            with (output / (label + '.log')).open('wb') as log:
                process = subprocess.Popen([str(binary), '--nocapture'], env=dict(os.environ, TMPDIR=str(tmp)),
                                           cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                try:
                    code = process.wait(timeout=420)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    code = 124
            # Metrics contain fixture diagnostics only; do not archive any profiles.
            for path in tmp.glob('*.jsonl'):
                shutil.copy2(path, output / (label + '-metrics.jsonl'))
            shutil.rmtree(tmp)
            report['checks'].append({'name': label, 'exit_code': code,
                                     'seconds': time.monotonic() - started, 'ephemeral_first': first})
        report['passed'] = report['checks'][-1]['exit_code'] == 0
        report['baseline_failed'] = report['checks'][0]['exit_code'] != 0
        report['binary_unchanged'] = hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest() == report['binary_sha256']
        report['passed'] = report['passed'] and report['binary_unchanged']
    except Exception as error:
        report['error'] = str(error)
    finally:
        restored = subprocess.run(['sudo', 'sysctl', '-w', key + '=' + old], check=False).returncode == 0
        report['port_setting_restored'] = restored and subprocess.check_output(['sysctl', '-n', key], text=True).strip() == old
        report['source_unchanged'] = hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
        report['passed'] = report['passed'] and report['port_setting_restored'] and report['source_unchanged']
        (output / 'summary.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
