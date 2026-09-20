#!/usr/bin/env python3
"""Build independent application consumers and record native stripped executable sizes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'examples/rust-integration/Cargo.toml'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--measure', action='store_true')
    parser.add_argument('--profiles', nargs='+', choices=('3', 's', 'z'), default=['3', 's', 'z'])
    parser.add_argument('--modes', nargs='+', choices=('ipc', 'embedded'), default=['ipc', 'embedded'])
    parser.add_argument('--output', type=Path, default=ROOT / 'target/rust-integration-evidence')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.setdefault('CARGO_BUILD_JOBS', '2')
    environment.setdefault('CARGO_TARGET_DIR', str(ROOT / 'target/rust-integrations'))
    target = Path(environment['CARGO_TARGET_DIR']).resolve()
    report = {'schema': 1, 'system': platform.system(), 'machine': platform.machine(),
              'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
              'panic': 'unwind', 'lto': True, 'codegen_units': 1, 'stripped': True, 'graphs': {}, 'binaries': []}
    # Retain exact consumer code and manifest digest alongside the source revision.
    report['consumer_sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in [MANIFEST, MANIFEST.parent / 'src/main.rs']}
    for mode in args.modes:
        options = ['--manifest-path', str(MANIFEST), '--no-default-features', '--features', mode]
        # cargo metadata includes inactive optional dependency edges. cargo tree
        # reports the actual target's resolved normal/build graph.
        tree = subprocess.check_output(['cargo', 'tree', *options, '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}|{f}'], cwd=ROOT, env=environment, text=True)
        graph = {}
        for line in tree.splitlines():
            package, features = line.split('|', 1)
            name = package.split()[0]
            graph[name] = sorted(set(graph.get(name, [])) | set(filter(None, features.removesuffix(' (*)').strip().split(','))))
        report['graphs'][mode] = graph
        if mode == 'ipc':
            forbidden = {'gcoms-node', 'gcoms-runtime', 'gcoms-file-transfer', 'gcoms-crypto', 'gcoms-mls', 'gcoms-routing', 'gcoms-rpc', 'gcoms-rpc-macros', 'reqwest', 'rustls', 'aes-gcm', 'argon2'}
            if forbidden & graph.keys():
                raise RuntimeError(f'IPC unexpectedly links host dependencies: {sorted(forbidden & graph.keys())}')
        if 'rt-multi-thread' in graph.get('tokio', []):
            raise RuntimeError(f'{mode} forces a multithread Tokio runtime')
        if 'gcoms-rpc' in graph:
            raise RuntimeError(f'{mode} unexpectedly enables typed RPC')
        if not args.measure:
            subprocess.run(['cargo', 'check', *options, '--locked'], cwd=ROOT, env=environment, check=True)
            continue
        for profile in args.profiles:
            build_env = dict(environment, CARGO_PROFILE_RELEASE_OPT_LEVEL=profile, CARGO_PROFILE_RELEASE_LTO='true',
                             CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1', CARGO_PROFILE_RELEASE_STRIP='symbols', CARGO_PROFILE_RELEASE_PANIC='unwind')
            subprocess.run(['cargo', 'build', *options, '--locked', '--release'], cwd=ROOT, env=build_env, check=True)
            executable = target / 'release' / ('gcoms-integration.exe' if os.name == 'nt' else 'gcoms-integration')
            retained = output / f'{mode}-opt-{profile}{executable.suffix}'
            shutil.copy2(executable, retained)
            subprocess.run([str(retained)], check=True, stdout=subprocess.DEVNULL)
            data = retained.read_bytes()
            report['binaries'].append({'mode': mode, 'opt_level': profile, 'bytes': len(data),
                                       'sha256': hashlib.sha256(data).hexdigest(), 'artifact': retained.name})
            (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'graphs': {k: len(v) for k, v in report['graphs'].items()}, 'binaries': report['binaries']}, indent=2))


if __name__ == '__main__':
    main()
