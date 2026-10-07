#!/usr/bin/env python3
"""Repeat one native regression, retaining its actual source and each verdict."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


TEST = ('node::persist::tests::'
        'component_authority_actual_signed_join_v15_migration_and_cold_member_reopen')
CONTROL = ('node::persist::tests::'
           'machine_checkpoint_after_authenticated_post_export_ack_prevents_secret_reuse')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=root):
        raise ValueError('native qualification requires unchanged committed source')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    report = {'schema': 1, 'source': source, 'test': TEST, 'platform': sys.platform,
              'started_at': int(time.time()), 'passed': False, 'runs': []}
    command = ['cargo', '+1.98.0', 'test', '--locked', '-p', 'gcoms-node',
               '--all-features', '--lib', TEST, '--']
    try:
        # A renamed/missing test must not silently turn three empty runs green.
        listed = subprocess.run(command + ['--exact', '--list'], cwd=root,
                                capture_output=True, text=True, timeout=1800)
        (output / 'compile.log').write_text(listed.stderr + listed.stdout)
        listed.check_returncode()
        if listed.stdout.splitlines().count(TEST + ': test') != 1:
            raise ValueError('expected exactly one cold member recovery test')
        control_command = [*command[:-2], CONTROL, '--']
        control_list = subprocess.run(control_command + ['--exact', '--list'], cwd=root,
                                      capture_output=True, text=True, timeout=120)
        control_list.check_returncode()
        if control_list.stdout.splitlines().count(CONTROL + ': test') != 1:
            raise ValueError('expected exactly one authenticated checkpoint control')
        with (output / 'checkpoint-control.log').open('wb') as log:
            control = subprocess.run(control_command + ['--exact', '--test-threads=1', '--nocapture'],
                                     cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        report['checkpoint_control'] = {'test': CONTROL, 'exit_code': control.returncode}
        control.check_returncode()
        for attempt in range(1, 4):
            with (output / f'run-{attempt}.log').open('wb') as log:
                result = subprocess.run(command + ['--exact', '--test-threads=1', '--nocapture'],
                                        cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=120)
            report['runs'].append({'attempt': attempt, 'exit_code': result.returncode})
            result.check_returncode()
        if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=root):
            raise ValueError('source changed during native qualification')
        report['passed'] = True
    finally:
        report['finished_at'] = int(time.time())
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
