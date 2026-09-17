#!/usr/bin/env python3
"""Build actual package archives and isolated consumers without publishing."""
import argparse, json, os, subprocess, tarfile, tempfile, tomllib
from pathlib import Path
root = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--gchat', type=Path)
p.add_argument('--offline', action='store_true')
p.add_argument('--output', type=Path, default=root / 'target/package-check')
a = p.parse_args()
out = a.output.resolve(); out.mkdir(parents=True, exist_ok=True)
env = dict(os.environ)
env.setdefault('CARGO_BUILD_JOBS', '2')

def run(args, cwd=root, **kwargs):
    print('+ ' + ' '.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True, **kwargs)

metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version=1'], cwd=root))
packages = [p for p in metadata['packages'] if p['id'] in metadata['workspace_members'] and p['publish'] != []]
args = ['cargo', 'package', '--allow-dirty', '--no-verify', '--target-dir', out]
for package in packages: args += ['-p', package['name']]
if a.offline: args += ['--offline']
run(args)
with tempfile.TemporaryDirectory(prefix='gcoms-consumer-') as tmp:
    temp = Path(tmp)
    patch = ['[patch.crates-io]']
    for package in packages:
        name, version = package['name'], package['version']
        archive = out / 'package' / f'{name}-{version}.crate'
        with tarfile.open(archive) as tar:
            tar.extractall(temp, filter='data')
        extracted = temp / f'{name}-{version}'
        manifest = tomllib.loads((extracted / 'Cargo.toml').read_text())
        tables = [manifest] + list(manifest.get('target', {}).values())
        for table in tables:
            for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                assert all('path' not in v for v in table.get(kind, {}).values() if isinstance(v, dict)), f'{name}: unnormalized dependency'
        for license in ('LICENSE-MIT', 'LICENSE-APACHE'):
            assert (extracted / license).is_file(), f'{name}: missing {license}'
        patch.append(f'{json.dumps(name)} = {{ path = {json.dumps(str(extracted))} }}')
    config = temp / 'packages.toml'; config.write_text('\n'.join(patch) + '\n')
    consumer = temp / 'consumer'; (consumer / 'src').mkdir(parents=True)
    (consumer / 'Cargo.toml').write_text('[package]\nname="external-gcoms-consumer"\nversion="0.0.0"\nedition="2021"\n[dependencies]\ncomms={package="gcoms-rpc",version="0.1.0",features=["file-store"]}\n')
    (consumer / 'src/lib.rs').write_text((root / 'examples/renamed-dependency/src/lib.rs').read_text())
    base = ['cargo', '--config', config, 'check', '--target-dir', out / 'consumer-target']
    if a.offline: base += ['--offline']
    run(base, cwd=consumer)
    if a.gchat:
        run(base + ['--workspace', '--all-features'], cwd=a.gchat.resolve())
    run(['npm', 'run', 'build'])
    run(['npm', 'pack', '--workspace', '@gcoms/rpc', '--workspace', '@gcoms/rpc-codegen', '--pack-destination', out])
    npm_consumer = temp / 'npm'; npm_consumer.mkdir()
    (npm_consumer / 'package.json').write_text('{"private":true,"type":"module"}\n')
    install = ['npm', 'install', '--ignore-scripts', '--no-audit', '--no-fund', out / 'gcoms-rpc-0.1.0.tgz', out / 'gcoms-rpc-codegen-0.1.0.tgz']
    if a.offline: install += ['--offline']
    run(install, cwd=npm_consumer)
    run(['node', '--input-type=module', '-e', "import {RpcClient} from '@gcoms/rpc'; import '@gcoms/rpc/wire'; import {serviceBindings,validators} from '@gcoms/rpc-codegen'; if (![RpcClient,serviceBindings,validators].every(x=>typeof x==='function')) throw Error('exports'); console.log('npm package exports passed')"], cwd=npm_consumer)
(out / 'summary.json').write_text(json.dumps({'rust_packages': [p['name'] for p in packages], 'rust_external_alias_consumer': 'passed', 'npm_archive_consumer': 'passed', 'gchat_rust': 'passed' if a.gchat else 'not run', 'published': False}, indent=2)+'\n')
print('Package archives and isolated consumers passed; nothing published.')
