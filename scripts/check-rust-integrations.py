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
import struct

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'examples/rust-integration/Cargo.toml'


def binary_imports(path):
    """Record native loader dependencies without requiring dumpbin on Windows."""
    if os.name == 'nt':
        data = path.read_bytes()
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        if data[:2] != b'MZ' or data[pe:pe + 4] != b'PE\0\0':
            raise RuntimeError('expected a native PE executable')
        optional = pe + 24
        magic = struct.unpack_from('<H', data, optional)[0]
        directories = optional + {0x10b: 96, 0x20b: 112}[magic]
        imports = struct.unpack_from('<I', data, directories + 8)[0]
        count = struct.unpack_from('<H', data, pe + 6)[0]
        table = optional + struct.unpack_from('<H', data, pe + 20)[0]
        sections = [struct.unpack_from('<IIII', data, table + i * 40 + 8) for i in range(count)]
        def offset(rva):
            for virtual_size, virtual_address, raw_size, raw_offset in sections:
                if virtual_address <= rva < virtual_address + min(virtual_size, raw_size):
                    return raw_offset + rva - virtual_address
            raise RuntimeError('PE import points outside file-backed sections')
        if not imports:
            return []
        found = []
        cursor = offset(imports)
        while any(data[cursor:cursor + 20]):
            name = offset(struct.unpack_from('<I', data, cursor + 12)[0])
            end = data.index(0, name, min(name + 512, len(data)))
            found.append(data[name:end].decode('ascii'))
            cursor += 20
            if len(found) > 256:
                raise RuntimeError('too many PE imports')
        return sorted(found)
    if platform.system() == 'Darwin':
        lines = subprocess.check_output(['otool', '-L', str(path)], text=True).splitlines()[1:]
        return sorted(line.strip().split(' (', 1)[0] for line in lines)
    lines = subprocess.check_output(['readelf', '-d', str(path)], text=True).splitlines()
    return sorted(line.split('[', 1)[1].split(']', 1)[0] for line in lines if '(NEEDED)' in line)


def compare_baseline(report, path):
    baseline = json.loads(path.read_text())
    for field in ('system', 'machine', 'rustc', 'panic', 'lto', 'codegen_units', 'stripped'):
        if baseline[field] != report[field]:
            raise RuntimeError(f'baseline {field} differs; establish a baseline for this toolchain')
    previous = {(item['mode'], item['opt_level']): item['bytes'] for item in baseline['binaries']}
    changes = []
    for item in report['binaries']:
        key = (item['mode'], item['opt_level'])
        if key not in previous:
            continue
        growth = item['bytes'] / previous[key] - 1
        changes.append({'mode': key[0], 'opt_level': key[1], 'growth_percent': round(growth * 100, 3)})
        if growth > 0.05:
            raise RuntimeError(f'{key} grew {growth:.1%}; exceeds the 5% size gate')
    report['baseline_comparison'] = changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--measure', action='store_true')
    parser.add_argument('--profiles', nargs='+', choices=('3', 's', 'z'), default=['3', 's', 'z'])
    parser.add_argument('--modes', nargs='+', choices=('ipc', 'embedded', 'network-client'), default=['ipc', 'embedded', 'network-client'])
    parser.add_argument('--output', type=Path, default=ROOT / 'target/rust-integration-evidence')
    parser.add_argument('--baseline', type=Path, help='Same-platform/toolchain summary; reject growth above 5 percent')
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
    source_paths = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().split('\0')
    source_paths = sorted({name for name in source_paths if name and (name.endswith('.rs') or Path(name).name in ('Cargo.toml', 'Cargo.lock')) and (ROOT / name).is_file()})
    report['source_sha256'] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}
    for mode in args.modes:
        options = ['--manifest-path', str(MANIFEST), '--no-default-features', '--features', mode]
        # cargo metadata includes inactive optional dependency edges. cargo tree
        # reports the actual target's resolved normal/build graph.
        tree = subprocess.check_output(['cargo', 'tree', *options, '--locked', '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}|{f}'], cwd=ROOT, env=environment, text=True)
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
        if mode == 'network-client':
            if any('relay-host' in graph.get(name, []) for name in ('gcoms-node', 'gcoms-runtime')):
                raise RuntimeError('Network client unexpectedly includes relay hosting')
            if 'quick-xml' in graph or 'embedded' in graph.get('gcoms-sdk', []):
                raise RuntimeError('Network client unexpectedly includes the legacy host dependency graph')
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
                                       'sha256': hashlib.sha256(data).hexdigest(), 'artifact': retained.name,
                                       'imports': binary_imports(retained)})
            (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    if args.measure and 'ipc' in args.modes:
        # The IPC client's footprint excludes this separate host. Report it too.
        build_env = dict(environment, CARGO_PROFILE_RELEASE_OPT_LEVEL='s', CARGO_PROFILE_RELEASE_LTO='true',
                         CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1', CARGO_PROFILE_RELEASE_STRIP='symbols', CARGO_PROFILE_RELEASE_PANIC='unwind')
        subprocess.run(['cargo', 'build', '-p', 'gcoms', '--no-default-features', '--features', 'daemon,files,gc2-carrier', '--bin', 'gcomsd', '--locked', '--release'], cwd=ROOT, env=build_env, check=True)
        executable = target / 'release' / ('gcomsd.exe' if os.name == 'nt' else 'gcomsd')
        retained = output / ('host-opt-s' + executable.suffix)
        shutil.copy2(executable, retained)
        data = retained.read_bytes()
        report['binaries'].append({'mode': 'host', 'opt_level': 's', 'bytes': len(data),
                                   'sha256': hashlib.sha256(data).hexdigest(), 'artifact': retained.name,
                                   'imports': binary_imports(retained)})
    if args.baseline:
        if not args.measure:
            raise RuntimeError('--baseline requires --measure')
        compare_baseline(report, args.baseline)
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    if any(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest for name, digest in report['source_sha256'].items()):
        raise RuntimeError('Rust source changed during size qualification; rerun after changes settle')
    print(json.dumps({'graphs': {k: len(v) for k, v in report['graphs'].items()}, 'binaries': report['binaries']}, indent=2))


if __name__ == '__main__':
    main()
