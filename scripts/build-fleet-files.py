#!/usr/bin/env python3
"""Build source-bound fleet executables without rewriting repository lockfiles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from source_snapshot import snapshot, unchanged

ROOT = Path(__file__).resolve().parents[1]

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gchat', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, default=ROOT / 'target/fleet-build-cache')
    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    sources = {'gcoms': ROOT, 'gchat': args.gchat.resolve()}
    report = {'schema': 1, 'passed': False, 'sources': {}, 'commands': [], 'artifacts': {}}
    try:
        for name, root in sources.items():
            files = snapshot(root, output / name)
            report['sources'][name] = {'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                'files': files, 'snapshot_sha256': hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()}
        patches = ['[patch.crates-io]']
        gcoms = output / 'gcoms'
        members = tomllib.loads((gcoms / 'Cargo.toml').read_text())['workspace']['members']
        for member in members:
            for folder in sorted(gcoms.glob(member)):
                name = tomllib.loads((folder / 'Cargo.toml').read_text())['package']['name']
                if name.startswith('gcoms-'):
                    patches.append(f'{json.dumps(name)} = {{ path = {json.dumps(str(folder))} }}')
        patch = output / 'source.toml'
        patch.write_text('\n'.join(patches) + '\n')
        env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()))
        env.setdefault('CARGO_BUILD_JOBS', '4')
        commands = [
            ('gcoms', ['cargo', 'build', '--release', '--offline', '--locked', '-p', 'gcoms-node', '--bin', 'gcnode', '--features', 'client-persist,experimental-gc2']),
            ('gchat', ['cargo', 'build', '--release', '--offline', '--config', str(patch), '-p', 'gchat-tui', '--bin', 'gchat', '--features', 'gc2-carrier']),
            ('gchat', ['cargo', 'build', '--release', '--offline', '--config', str(patch), '-p', 'gchat-core', '--example', 'fleet_probe', '--features', 'gc2-carrier']),
        ]
        for name, command in commands:
            report['commands'].append({'repository': name, 'argv': command})
            subprocess.run(command, cwd=output / name, env=env, check=True)
        (output / 'bin').mkdir()
        for name, relative in [('gcnode', 'gcnode'), ('gchat', 'gchat'), ('fleet_probe', 'examples/fleet_probe')]:
            dest = output / 'bin' / name
            shutil.copy2(args.target_dir / 'release' / relative, dest)
            report['artifacts'][name] = {'sha256': digest(dest), 'size': dest.stat().st_size}
        for name, root in sources.items():
            report['sources'][name]['unchanged'] = unchanged(root, report['sources'][name]['files'])
            report['sources'][name]['resolved_lock_sha256'] = digest(output / name / 'Cargo.lock')
        report['passed'] = all(v['unchanged'] for v in report['sources'].values())
        if not report['passed']:
            raise RuntimeError('source changed during the build; rebuild before deployment')
    except Exception as exc:
        report['error'] = str(exc)
        raise
    finally:
        (output / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(output / 'build.json')

if __name__ == '__main__':
    main()
