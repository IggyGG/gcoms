#!/usr/bin/env python3
"""Build mutually exclusive native mobile packages with recorded sizes and inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'mobile/native/Cargo.toml'
NDK_VERSION = '28.2.13676358'


def run(command, env=None, **kwargs):
    subprocess.run([str(value) for value in command], check=True, env=env, **kwargs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platform', choices=['android', 'apple'])
    parser.add_argument('--roles', nargs='+', choices=['client', 'relay'], default=['client', 'relay'])
    parser.add_argument('--profiles', nargs='+', choices=['3', 's', 'z'], default=['z'])
    parser.add_argument('--fixtures', action='store_true', help='Non-distributable simulator/emulator qualification build')
    parser.add_argument('--baseline', type=Path, help='Same-toolchain native summary; reject size growth above 5 percent')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/mobile')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target/mobile-build')).resolve()
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target))
    environment.setdefault('CARGO_BUILD_JOBS', '2')
    report = {
        'schema': 1, 'platform': args.platform, 'fixtures': args.fixtures,
        'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
        'panic': 'unwind', 'lto': True, 'codegen_units': 1, 'artifacts': [], 'graphs': {}
    }
    sources = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().split('\0')
    report['source_sha256'] = {name: digest(ROOT / name) for name in sorted(set(sources)) if name and (ROOT / name).is_file() and (name.startswith('mobile/') or name.startswith('crates/') or name in ('Cargo.toml', 'Cargo.lock', 'scripts/build-mobile.py'))}
    if args.platform == 'android':
        sdk = Path(os.environ['ANDROID_HOME'])
        ndk = Path(os.environ.get('ANDROID_NDK_HOME', sdk / 'ndk' / NDK_VERSION))
        host = 'darwin-x86_64' if platform.system() == 'Darwin' else 'linux-x86_64'
        llvm = ndk / 'toolchains/llvm/prebuilt' / host / 'bin'
        targets = [('aarch64-linux-android', 'arm64-v8a'), ('x86_64-linux-android', 'x86_64')]
        report['ndk'] = (ndk / 'source.properties').read_text()
    else:
        if platform.system() != 'Darwin':
            raise RuntimeError('Apple packages require a macOS runner with Xcode')
        targets = [('aarch64-apple-ios', 'device'), ('aarch64-apple-ios-sim', 'sim-arm64'), ('x86_64-apple-ios', 'sim-x86_64')]
        report['xcode'] = subprocess.check_output(['xcodebuild', '-version'], text=True)
        environment['IPHONEOS_DEPLOYMENT_TARGET'] = '15.0'
    run(['rustup', 'target', 'add', *[t for t, _ in targets]])
    for role in args.roles:
        for profile in args.profiles:
            build_env = dict(environment, CARGO_PROFILE_RELEASE_OPT_LEVEL=profile)
            for triple, label in targets:
                env = dict(build_env)
                if args.platform == 'android':
                    compiler = str(llvm / (triple + '26-clang'))
                    env['CARGO_TARGET_' + triple.replace('-', '_').upper() + '_LINKER'] = compiler
                    env['CC_' + triple.replace('-', '_')] = compiler
                    env['AR_' + triple.replace('-', '_')] = str(llvm / 'llvm-ar')
                    env['RUSTFLAGS'] = env.get('RUSTFLAGS', '') + ' -C link-arg=-Wl,-z,max-page-size=16384'
                features = role + (',fixtures' if args.fixtures else '')
                tree = subprocess.check_output(['cargo', 'tree', '--manifest-path', str(MANIFEST), '--locked',
                    '--no-default-features', '--features', features, '--target', triple,
                    '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}|{f}'], env=env, text=True)
                graph = {}
                for line in tree.splitlines():
                    package, active = line.split('|', 1)
                    name = package.split()[0]
                    graph[name] = sorted(set(graph.get(name, [])) | set(filter(None, active.removesuffix(' (*)').strip().split(','))))
                if 'rt-multi-thread' in graph.get('tokio', []) or 'gcoms-rpc' in graph:
                    raise RuntimeError('Mobile package pulls in optional RPC or multithread scheduling')
                if role == 'client' and ('relay-host' in graph.get('gcoms-node', []) or 'quick-xml' in graph):
                    raise RuntimeError('Client package pulls in relay hosting')
                report['graphs'][role + '/' + triple] = graph
                run(['cargo', 'build', '--manifest-path', MANIFEST, '--locked', '--release', '--no-default-features', '--features', features, '--target', triple], env)
                name = 'libgcoms_mobile.so' if args.platform == 'android' else 'libgcoms_mobile.a'
                library = target / triple / 'release' / name
                retained = output / 'evidence' / f'{role}-{triple}-opt-{profile}{library.suffix}'
                retained.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(library, retained)
                if args.platform == 'android':
                    run([llvm / 'llvm-strip', '--strip-unneeded', retained])
                    headers = subprocess.check_output([str(llvm / 'llvm-readelf'), '-Wl', str(retained)], text=True)
                    loads = [line.split() for line in headers.splitlines() if line.lstrip().startswith('LOAD ')]
                    if not loads or any(int(line[-1], 16) < 16384 for line in loads):
                        raise RuntimeError('Native library lacks 16 KiB load alignment')
                    for line in headers.splitlines():
                        parts = line.split()
                        if parts and parts[0] == 'GNU_RELRO' and (int(parts[2], 16) + int(parts[5], 16)) % 16384:
                            raise RuntimeError('Native library lacks 16 KiB RELRO alignment')
                    destination = output / 'android' / role / label / name
                else:
                    destination = output / 'apple' / role / label / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(retained, destination)
                report['artifacts'].append({'role': role, 'target': triple, 'opt_level': profile,
                    'kind': 'shared_library' if args.platform == 'android' else 'static_archive',
                    'bytes': retained.stat().st_size, 'sha256': digest(retained), 'artifact': str(retained.relative_to(output))})
                (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
            if args.platform == 'apple':
                package_apple(output, role)
            else:
                (output / 'android' / role / 'build.json').write_text(json.dumps({'fixtures': args.fixtures, 'role': role, 'revision': report['revision']}) + '\n')
    if args.baseline:
        baseline = json.loads(args.baseline.read_text())
        for field in ('platform', 'fixtures', 'rustc', 'ndk', 'xcode', 'panic', 'lto', 'codegen_units'):
            if baseline.get(field) != report.get(field):
                raise RuntimeError(f'baseline {field} differs; establish a baseline for this toolchain')
        previous = {(item['role'], item['target'], item['opt_level']): item['bytes'] for item in baseline['artifacts']}
        for item in report['artifacts']:
            key = (item['role'], item['target'], item['opt_level'])
            if key in previous and item['bytes'] > previous[key] * 1.05:
                raise RuntimeError(f'{key} exceeds the 5 percent native size gate')
    for name, expected in report['source_sha256'].items():
        if digest(ROOT / name) != expected:
            raise RuntimeError('Mobile source changed during qualification; rerun against settled inputs')
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['artifacts'], indent=2))


def package_apple(output, role):
    native = output / 'apple' / role
    package = output / 'packages' / ('GComsClient' if role == 'client' else 'GComsRelay')
    package.mkdir(parents=True, exist_ok=True)
    simulator = native / 'libgcoms_sim.a'
    run(['xcrun', 'lipo', '-create', native / 'sim-arm64/libgcoms_mobile.a', native / 'sim-x86_64/libgcoms_mobile.a', '-output', simulator])
    framework = package / 'GComsNative.xcframework'
    if framework.exists():
        shutil.rmtree(framework)  # Generated package under the selected output only.
    headers = native / 'include'
    headers.mkdir(exist_ok=True)
    shutil.copy2(ROOT / 'mobile/native/include/gcoms_mobile.h', headers)
    (headers / 'module.modulemap').write_text('module CGComs { header "gcoms_mobile.h" export * }\n')
    run(['xcodebuild', '-create-xcframework', '-library', native / 'device/libgcoms_mobile.a', '-headers', headers, '-library', simulator, '-headers', headers, '-output', framework])
    for directory in ('Sources', 'Tests'):
        shutil.copytree(ROOT / 'mobile/apple' / directory, package / directory, dirs_exist_ok=True)
    (package / 'Package.swift').write_text('''// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "GComs",
    platforms: [.iOS(.v15)],
    products: [.library(name: "GComs", targets: ["GComs"])],
    targets: [
        .binaryTarget(name: "CGComs", path: "GComsNative.xcframework"),
        .target(name: "GComs", dependencies: ["CGComs"], linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration"), .linkedLibrary("resolv")]),
        .testTarget(name: "GComsTests", dependencies: ["GComs"])
    ]
)
''')


if __name__ == '__main__':
    main()
