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

def source_patches(gcoms):
    patches = ['[patch.crates-io]']
    members = tomllib.loads((gcoms / 'Cargo.toml').read_text())['workspace']['members']
    for member in members:
        for folder in sorted(gcoms.glob(member)):
            if not folder.resolve().is_relative_to(gcoms.resolve()):
                raise ValueError('workspace member escapes paired source')
            name = tomllib.loads((folder / 'Cargo.toml').read_text())['package']['name']
            if name == 'gcoms' or name.startswith('gcoms-'):
                patches.append(f'{json.dumps(name)} = {{ path = {json.dumps(str(folder))} }}')
    return '\n'.join(patches) + '\n'


def supplied_relay(directory, sources):
    """Only the exact frozen production feature graph may supply the relay."""
    receipt = json.loads((directory / 'receipt.json').read_text())
    command = ['cargo', 'build', '--locked', '--release', '-p', 'gcoms-node',
               '-p', 'gcoms-catalog', '-p', 'gcoms-channel-service', '--features',
               'gcoms-node/experimental-gc2,gcoms-node/push-gateway,gcoms-catalog/experimental-gc2']
    if (receipt.get('schema') != 1 or receipt.get('kind') != 'linux_native_services'
            or receipt.get('passed') is not True or receipt.get('commands') != [command]
            or receipt.get('target') != 'x86_64-unknown-linux-gnu'
            or receipt.get('rustc') != subprocess.check_output(['rustc', '-vV'], text=True)
            or receipt.get('rustflags') != os.environ.get('RUSTFLAGS', '')
            or receipt.get('compiler_environment') != {
                **{key: os.environ.get(key, '') for key in
                   ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET')},
                **{key: value for key, value in os.environ.items()
                   if key.startswith('CARGO_PROFILE_RELEASE_')}}):
        raise ValueError('supplied relay is not the exact production build')
    for name, root in sources.items():
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
        if receipt.get('sources', {}).get(name, {}).get('commit') != commit:
            raise ValueError('supplied relay source differs from the fixture')
    binary = directory / 'gcnode'
    if not binary.is_file() or binary.is_symlink() or digest(binary) != receipt.get('files', {}).get('gcnode'):
        raise ValueError('supplied production relay bytes changed')
    return receipt

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gchat', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, default=ROOT / 'target/fleet-build-cache')
    p.add_argument('--fetch', action='store_true',
                   help='fetch dependencies in the isolated source copy before the offline build')
    p.add_argument('--relay-build', type=Path, help='verified production service build supplying gcnode unchanged')
    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    sources = {'gcoms': ROOT, 'gchat': args.gchat.resolve()}
    relay = supplied_relay(args.relay_build.resolve(), sources) if args.relay_build else None
    report = {'schema': 1, 'passed': False, 'sources': {}, 'commands': [], 'artifacts': {}}
    try:
        for name, root in sources.items():
            files = snapshot(root, output / name)
            report['sources'][name] = {'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                'files': files, 'snapshot_sha256': hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()}
        gcoms = output / 'gcoms'
        patch = output / 'source.toml'
        patch.write_text(source_patches(gcoms))
        env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()))
        env.setdefault('CARGO_BUILD_JOBS', '4')
        commands = [
            # Select the relay, client and both qualification hosts together, so
            # Cargo compiles their common feature graph once. The relay package
            # is the source-patched dependency from the frozen companion tree.
            ('gchat', ['cargo', 'build', '--release', '--offline', '--config', str(patch),
                       '-p', 'gcoms-node', '-p', 'gchat-tui', '-p', 'gchat-core',
                       '--bin', 'gcnode', '--bin', 'gchat', '--example', 'fleet_probe',
                       '--example', 'turnover_daemon', '--features',
                       'gc2-carrier,gcoms-node/client-persist,gcoms-node/experimental-gc2']),
        ]
        if args.fetch:
            commands.insert(0, ('gchat', ['cargo', 'fetch', '--config', str(patch)]))
        if relay is not None:
            # Compile only the three fixture/client executables. Their graph is
            # deliberately separate from the production relay's push-gateway graph.
            command = commands[-1][1]
            position = command.index('gcnode')
            del command[position - 1:position + 1]
            report['provided_relay'] = {'receipt_sha256': digest(args.relay_build / 'receipt.json'),
                                        'receipt': relay}
        for name, command in commands:
            report['commands'].append({'repository': name, 'argv': command})
            subprocess.run(command, cwd=output / name, env=env, check=True)
        (output / 'bin').mkdir()
        for name, relative in [('gcnode', 'gcnode'), ('gchat', 'gchat'), ('fleet_probe', 'examples/fleet_probe'), ('turnover_daemon', 'examples/turnover_daemon')]:
            dest = output / 'bin' / name
            source = args.relay_build / 'gcnode' if name == 'gcnode' and relay is not None else args.target_dir / 'release' / relative
            shutil.copy2(source, dest)
            report['artifacts'][name] = {'sha256': digest(dest), 'size': dest.stat().st_size}
            if name == 'gcnode' and relay is not None and digest(dest) != relay['files']['gcnode']:
                raise ValueError('supplied production relay changed during fixture build')
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
