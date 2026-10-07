#!/usr/bin/env python3
"""Join the passing Intel backend and three isolated size jobs from one CI attempt."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODES = ('ipc', 'embedded', 'network-client')
PROFILES = ('3', 's', 'z')
SPEC = importlib.util.spec_from_file_location('rust_sizes', ROOT / 'scripts/check-rust-integrations.py')
SIZES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIZES)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('qualification record must be an object')
    return value


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def identity(revision, run_id, attempt):
    return {'schema': 1, 'revision': revision, 'run_id': str(run_id), 'run_attempt': str(attempt)}


def clean_revision(root, revision):
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)
    if actual != revision or dirty:
        raise ValueError('qualification source is not the clean expected revision')


def record(root, directory, binding, mode=None):
    """Called only after the corresponding command has exited successfully."""
    clean_revision(root, binding['revision'])
    result = dict(binding, passed=True)
    if mode is None:
        if (directory / 'source.txt').read_text().strip() != binding['revision']:
            raise ValueError('backend source differs')
        result.update(system=platform.system(), machine=platform.machine(),
                      rustc=subprocess.check_output(['rustc', '-Vv'], text=True),
                      native_log_sha256=digest(directory / 'native.log'))
        name = 'native-backend.json'
    else:
        report = read(directory / 'summary.json')
        if (report.get('passed') is not True or report.get('dirty') is not False
                or report.get('revision') != binding['revision']
                or set(report.get('graphs', {})) != {mode}):
            raise ValueError('consumer shard did not qualify the expected source/mode')
        result.update(mode=mode, summary_sha256=digest(directory / 'summary.json'))
        name = 'qualification-shard.json'
    write(directory / name, result)


def checked_file(directory, name, expected_hash):
    if not isinstance(name, str) or Path(name).name != name or name in ('', '.', '..'):
        raise ValueError('qualification artifact name is not a basename')
    path = directory / name
    if not path.is_file() or path.is_symlink() or digest(path) != expected_hash:
        raise ValueError('qualification artifact hash differs: ' + name)
    return path


def check_binding(value, binding):
    if (any(value.get(key) != expected for key, expected in binding.items() if key != 'run_attempt')
            or value.get('passed') is not True):
        raise ValueError('qualification source, attempt or pass binding differs')
    attempt = value.get('run_attempt')
    if (not isinstance(attempt, str) or not re.fullmatch('[1-9][0-9]*', attempt)
            or int(attempt) > int(binding['run_attempt'])):
        raise ValueError('qualification attempt binding differs')


def latest_attempt(directories, prefix, marker, binding, mode=None):
    """Newest lane evidence must pass; never fall back past an incomplete attempt."""
    candidates = {}
    for directory in directories:
        match = re.fullmatch(re.escape(prefix) + r'([1-9][0-9]*)', directory.name)
        if not match:
            continue
        attempt = int(match[1])
        if attempt > int(binding['run_attempt']) or attempt in candidates:
            raise ValueError('duplicate or future artifact attempt')
        candidates[attempt] = directory
    if not candidates:
        raise ValueError('required qualification lane is missing')
    attempt = max(candidates)
    directory = candidates[attempt]
    value = read(directory / marker)  # Missing/partial newest evidence fails closed.
    check_binding(value, binding)
    if value['run_attempt'] != str(attempt) or (mode is not None and value.get('mode') != mode):
        raise ValueError('artifact name and qualification binding differ')
    return directory


def source_hashes(root):
    names = subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).decode().split('\0')
    return {name: digest(root / name) for name in sorted(set(names))
            if name and (name.endswith('.rs') or Path(name).name in ('Cargo.toml', 'Cargo.lock'))
            and (root / name).is_file()}


def isolated_graph(mode, graph):
    if not isinstance(graph, dict) or not graph or any(
            not isinstance(features, list) or any(not isinstance(value, str) for value in features)
            for features in graph.values()):
        raise ValueError('isolated graph is malformed')
    if mode == 'ipc':
        forbidden = {'gcoms-node', 'gcoms-runtime', 'gcoms-file-transfer', 'gcoms-crypto',
                     'gcoms-mls', 'gcoms-routing', 'gcoms-rpc', 'gcoms-rpc-macros',
                     'reqwest', 'rustls', 'aes-gcm', 'argon2'}
        if forbidden & graph.keys():
            raise ValueError('IPC graph includes host dependencies')
    if mode == 'network-client' and (
            any('relay-host' in graph.get(name, []) for name in ('gcoms-node', 'gcoms-runtime'))
            or 'quick-xml' in graph or 'embedded' in graph.get('gcoms-sdk', [])):
        raise ValueError('network client graph includes host dependencies')
    if 'rt-multi-thread' in graph.get('tokio', []) or 'gcoms-rpc' in graph:
        raise ValueError('isolated graph includes a forbidden runtime/RPC feature')


def compatibility(root, directory):
    result = read(directory / 'summary.json')
    contract = read(root / 'release/contracts/application-0.1.49/contract.json')
    if (result.get('schema') != 1 or result.get('passed') is not True
            or result.get('consumer') != contract
            or digest(root / 'release/contracts/application-0.1.49/main.rs') != contract['sha256']):
        raise ValueError('released facade compatibility proof differs')
    checks = result.get('checks', [])
    if len(checks) != len(MODES) or {item.get('mode') for item in checks} != set(MODES):
        raise ValueError('released facade compatibility modes are incomplete')
    for item in checks:
        if item.get('passed') is not True or item.get('log') != item['mode'] + '.log':
            raise ValueError('released facade compatibility mode failed')
        checked_file(directory, item['log'], item.get('sha256'))


def merge(root, backend, shards, output, baseline, binding):
    if len(shards) != len(MODES):
        raise ValueError('exactly three consumer shards are required')
    if output.exists() and any(output.iterdir()):
        raise ValueError('aggregate output must be fresh')
    native = read(backend / 'native-backend.json')
    check_binding(native, binding)
    if native.get('system') != 'Darwin' or native.get('machine') != 'x86_64':
        raise ValueError('backend is not native Intel Mac')
    if (backend / 'source.txt').read_text().strip() != binding['revision']:
        raise ValueError('backend source differs')
    checked_file(backend, 'native.log', native.get('native_log_sha256'))
    inputs = source_hashes(root)
    consumers = {path.relative_to(root).as_posix(): digest(path) for path in (
        root / 'examples/rust-integration/Cargo.toml', root / 'examples/rust-integration/src/main.rs')}
    common = None
    graphs, binaries, modes, files = {}, [], set(), []
    attempts = {'backend': native['run_attempt'], 'consumers': {}}
    for directory in shards:
        marker = read(directory / 'qualification-shard.json')
        check_binding(marker, binding)
        mode = marker.get('mode')
        if mode not in MODES or mode in modes:
            raise ValueError('consumer mode missing or duplicated')
        modes.add(mode)
        attempts['consumers'][mode] = marker['run_attempt']
        checked_file(directory, 'summary.json', marker.get('summary_sha256'))
        report = read(directory / 'summary.json')
        if (report.get('passed') is not True or report.get('dirty') is not False
                or report.get('revision') != binding['revision']
                or report.get('system') != 'Darwin' or report.get('machine') != 'x86_64'
                or report.get('rustc') != native.get('rustc')
                or report.get('source_sha256') != inputs or report.get('consumer_sha256') != consumers
                or set(report.get('graphs', {})) != {mode}):
            raise ValueError('consumer source or isolated graph differs')
        isolated_graph(mode, report['graphs'][mode])
        shared = {key: value for key, value in report.items()
                  if key not in ('graphs', 'binaries', 'baseline_comparison')}
        if common is not None and common != shared:
            raise ValueError('consumer toolchain, profile or policy differs')
        common = shared
        expected = {(mode, profile) for profile in PROFILES}
        if mode == 'ipc':
            expected.add(('host', 's'))
        measured = report.get('binaries', [])
        if len(measured) != len(expected) or {(item.get('mode'), item.get('opt_level')) for item in measured} != expected:
            raise ValueError('consumer measurements are missing or duplicated')
        for item in measured:
            name = item['mode'] + '-opt-' + item['opt_level']
            if item.get('artifact') != name:
                raise ValueError('consumer artifact name differs')
            path = checked_file(directory, name, item.get('sha256'))
            if type(item.get('bytes')) is not int or path.stat().st_size != item['bytes']:
                raise ValueError('consumer artifact size differs')
            files.append(path)
        compatibility(root, directory / 'released-facade')
        graphs.update(report['graphs'])
        binaries.extend(measured)
    report = dict(common, graphs=graphs, binaries=sorted(binaries, key=lambda item: (item['mode'], item['opt_level'])))
    if report.get('size_policy') != SIZES.current_policy():
        raise ValueError('size policy differs from the current source')
    # Enforce the original baseline once more on the complete ten measurements.
    SIZES.compare_baseline(report, baseline)
    output.mkdir(parents=True, exist_ok=True)
    for path in files:
        shutil.copy2(path, output / path.name)
    for name in ('native.log', 'source.txt', 'native-backend.json'):
        shutil.copy2(backend / name, output / name)
    for directory in shards:
        mode = read(directory / 'qualification-shard.json')['mode']
        retained = output / 'shards' / mode
        retained.mkdir(parents=True)
        for name in ('summary.json', 'qualification-shard.json'):
            shutil.copy2(directory / name, retained / name)
        shutil.copytree(directory / 'released-facade', retained / 'released-facade')
        if mode == 'ipc':
            shutil.copytree(directory / 'released-facade', output / 'released-facade')
    write(output / 'summary.json', report)
    write(output / 'qualification-merge.json', dict(binding, passed=True, modes=list(MODES),
                                                  measurements=len(binaries), native_backend=True,
                                                  original_attempts=attempts))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('backend', 'shard', 'merge'))
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--mode', choices=MODES)
    parser.add_argument('--backend', type=Path)
    parser.add_argument('--shards', nargs='+', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    binding = identity(os.environ['GITHUB_SHA'], os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'])
    clean_revision(ROOT, binding['revision'])
    if args.command == 'merge':
        revision = binding['revision']
        backend = latest_attempt(list(args.backend.iterdir()),
                                 f'native-backend-macos-15-intel-{revision}-',
                                 'native-backend.json', binding)
        shards = [latest_attempt(args.shards, f'rust-integrations-intel-{mode}-{revision}-',
                                 'qualification-shard.json', binding, mode) for mode in MODES]
        merge(ROOT, backend, shards, args.output,
              ROOT / 'docs/evidence/rust-integrations-20260921/darwin-x86_64.json', binding)
    else:
        if not args.directory or (args.command == 'shard' and not args.mode):
            parser.error('recording requires --directory and shards require --mode')
        record(ROOT, args.directory, binding, args.mode if args.command == 'shard' else None)


if __name__ == '__main__':
    main()
