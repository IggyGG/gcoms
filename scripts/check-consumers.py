#!/usr/bin/env python3
"""Package and check isolated consumers without modifying original checkouts."""
import argparse
import hashlib
import json
import os
from pathlib import Path

NPM = 'npm.cmd' if os.name == 'nt' else 'npm'
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import uuid

from release_evidence import source_identity
from source_snapshot import snapshot, unchanged

ROOT = Path(__file__).resolve().parents[1]


def install_snapshot_npm(chat, archives, offline, run):
    """Resolve unpublished workspace dependencies only inside the disposable copy."""
    options = ['--ignore-scripts', '--no-audit', '--no-fund']
    if offline:
        options.append('--offline')
    # A local root requirement satisfies the workspace's versioned requirement.
    # npm updates this copy's lock/checksums; release manifests remain untouched.
    run([NPM, 'install', *options, '--package-lock-only', *archives], chat)
    run([NPM, 'ci', *options], chat)


def prepare_gchat_resources(chat, config, archives, args, out, env, run, report):
    install_snapshot_npm(chat, archives, args.offline, run)
    run([NPM, 'run', 'check'], chat)
    run([NPM, 'test'], chat)
    run([NPM, 'run', 'build'], chat)
    report['gchat_frontend'] = 'passed'
    # Resolve the standalone desktop lock in its disposable copy before the
    # notice collector's locked metadata step. Only the build target's graph
    # belongs in these native resources.
    target = env.get('CARGO_BUILD_TARGET')
    if not target:
        version = subprocess.check_output(['rustc', '-vV'], env=env, text=True)
        target = next(line.removeprefix('host: ') for line in version.splitlines()
                      if line.startswith('host: '))
    command = ['cargo', 'metadata', '--config', str(config), '--format-version=1',
               '--manifest-path', 'apps/client/src-tauri/Cargo.toml',
               '--all-features', '--filter-platform', target]
    if args.offline:
        command.append('--offline')
    metadata = subprocess.check_output(command, cwd=chat, env=env)
    metadata_path = out / 'gchat-desktop-metadata.json'
    metadata_path.write_bytes(metadata)
    run([sys.executable, 'scripts/collect-notices.py', '--rust-metadata', metadata_path], chat)
    notices = chat / 'third-party/generated'
    if not (notices / 'inventory.json').is_file():
        raise ValueError('GChat notice collector did not produce its inventory')
    shutil.copytree(notices, out / 'gchat-notices')
    return hashlib.sha256((notices / 'inventory.json').read_bytes()).hexdigest()


def qualify(root, chat, args, out, env, report):
    def run(command, cwd=root):
        print('+ ' + ' '.join(map(str, command)), flush=True)
        subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True)

    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--no-deps', '--format-version=1'], cwd=root, env=env))
    packages = [p for p in metadata['packages'] if p['id'] in metadata['workspace_members'] and p['publish'] != []]
    report.update(rust_packages=[p['name'] for p in packages],
                  rust_external_alias_consumer='not_run', npm_archive_consumer='not_run',
                  gchat_rust='not_run', gchat_frontend='not_run', gchat_desktop='not_run')
    command = ['cargo', 'package', '--locked', '--no-verify', '--target-dir', out]
    if not args.release:
        command += ['--allow-dirty']
    for package in packages:
        command += ['-p', package['name']]
    if args.offline:
        command += ['--offline']
    run(command)
    report['archive_sha256'] = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (out / 'package').glob('*.crate')
    }
    with tempfile.TemporaryDirectory(prefix='gc-archives-') as temporary:
        temp = Path(temporary)
        patches = ['[patch.crates-io]']
        for package in packages:
            name, version = package['name'], package['version']
            archive = out / 'package' / f'{name}-{version}.crate'
            with tarfile.open(archive) as tar:
                tar.extractall(temp, filter='data')
            extracted = temp / f'{name}-{version}'
            manifest = tomllib.loads((extracted / 'Cargo.toml').read_text())
            for table in [manifest] + list(manifest.get('target', {}).values()):
                for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                    if any('path' in value for value in table.get(kind, {}).values() if isinstance(value, dict)):
                        raise ValueError(f'{name}: unnormalized path dependency')
            for license in ('LICENSE-MIT', 'LICENSE-APACHE'):
                if not (extracted / license).is_file():
                    raise ValueError(f'{name}: missing {license}')
            patches.append(f'{json.dumps(name)} = {{ path = {json.dumps(str(extracted))} }}')
        config = temp / 'packages.toml'
        config.write_text('\n'.join(patches) + '\n')
        consumer = temp / 'consumer'; (consumer / 'src').mkdir(parents=True)
        deps = ['comms={package="gcoms",version="0.1.0",default-features=false,features=["embedded","ipc","rpc"]}']
        (consumer / 'Cargo.toml').write_text('[package]\nname="external-gcoms-consumer"\nversion="0.0.0"\nedition="2021"\n[dependencies]\n' + '\n'.join(deps) + '\n')
        (consumer / 'src/lib.rs').write_text((root / 'examples/renamed-dependency/src/lib.rs').read_text())
        build_target = (args.consumer_target_dir.resolve() if args.consumer_target_dir
                        else out / 'consumer-target')
        base = ['cargo', 'check', '--config', config, '--target-dir', build_target]
        if args.offline:
            base += ['--offline']
        run(base, consumer)
        report['rust_external_alias_consumer'] = 'passed'
        if chat:
            run(base + ['--workspace', '--all-features'], chat)
            report['gchat_rust'] = 'passed'
        npm_ci = [NPM, 'ci', '--ignore-scripts', '--no-audit', '--no-fund']
        if args.offline:
            npm_ci += ['--offline']
        run(npm_ci)
        run([NPM, 'run', 'build'])
        run([NPM, 'pack', '--workspace', '@gcoms/rpc', '--workspace', '@gcoms/rpc-codegen', '--pack-destination', out])
        archives = [out / 'gcoms-rpc-0.1.0.tgz', out / 'gcoms-rpc-codegen-0.1.0.tgz']
        report['archive_sha256'].update({
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in archives
        })
        npm = temp / 'npm'; npm.mkdir()
        (npm / 'package.json').write_text('{"private":true,"type":"module"}\n')
        install = [NPM, 'install', '--ignore-scripts', '--no-audit', '--no-fund', out / 'gcoms-rpc-0.1.0.tgz', out / 'gcoms-rpc-codegen-0.1.0.tgz']
        if args.offline:
            install += ['--offline']
        run(install, npm)
        run(['node', '--input-type=module', '-e', "import {RpcClient} from '@gcoms/rpc'; import '@gcoms/rpc/wire'; import {serviceBindings,validators} from '@gcoms/rpc-codegen'; if (![RpcClient,serviceBindings,validators].every(x=>typeof x==='function')) throw Error('exports'); console.log('npm package exports passed')"], npm)
        report['npm_archive_consumer'] = 'passed'
        if chat:
            report['gchat_notices_sha256'] = prepare_gchat_resources(
                chat, config, archives, args, out, env, run, report)
            run(base + ['--manifest-path', 'apps/client/src-tauri/Cargo.toml', '--locked'], chat)
            report['gchat_desktop'] = 'passed'
    archives = list((out / 'package').glob('*.crate')) + list(out.glob('*.tgz'))
    return {'archive_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in archives}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gchat', type=Path)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--release', action='store_true', help='require clean committed sources')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/package-check')
    parser.add_argument('--consumer-target-dir', type=Path,
                        help='reuse a Cargo build cache while keeping new archive/evidence output')
    args = parser.parse_args()
    out = args.output.resolve()
    if args.release and out.exists() and any(out.iterdir()):
        parser.error('--release needs a fresh output directory so archives cannot be replaced')
    out.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    report = {'status': 'failed', 'release': args.release, 'published': False, 'sources': {}}
    sources = {'gcoms': ROOT}
    if args.gchat:
        sources['gchat'] = args.gchat.resolve()
    hashes = {}
    env = dict(os.environ); env.setdefault('CARGO_BUILD_JOBS', '2')
    try:
        with tempfile.TemporaryDirectory(prefix='gc-pack-') as temporary:
            scratch = Path(temporary)
            for name, source in sources.items():
                if args.release:
                    source_identity(source)
                hashes[name] = snapshot(source, scratch / name, keep_vcs=True)
                report['sources'][name] = {'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip(),
                                           'files_sha256': hashes[name]}
            report.update(qualify(scratch / 'gcoms', scratch / 'gchat' if args.gchat else None, args, out, env, report))
            report['status'] = 'passed'
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        report['source_unchanged'] = bool(hashes) and all(unchanged(sources[name], value) for name, value in hashes.items())
        if not report['source_unchanged']:
            report['status'] = 'source_changed'
        reports = out / 'reports'; reports.mkdir(exist_ok=True)
        (reports / f'consumers-{run_id}.json').write_text(json.dumps(report, indent=2) + '\n')
        (out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    if report['status'] != 'passed':
        raise SystemExit('Source changed during package qualification; inspect retained report')
    print('Package archives and isolated consumers passed; original checkouts unchanged; nothing published.')


if __name__ == '__main__':
    main()
