#!/usr/bin/env python3
"""Audit selected source names/manifests. Never prints matched secret material."""
import json, re, subprocess, sys, tomllib
from pathlib import Path
root = Path(__file__).resolve().parents[1]
paths = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).decode().split('\0')
paths = sorted({p for p in paths if p})
errors = []
private = {'machine-agent', 'machine-identity', 'principal-binding', 'ghost-fleet-protocol', 'ghost-request-protocol', 'ghost-bootstrap-protocol', 'ghost-machine-commands', 'gc-machine-commands'}
for name in paths:
    path = root / name
    if not path.is_file():
        continue
    if path.is_symlink() and not path.resolve().is_relative_to(root):
        errors.append(f'{name}: external symlink')
    if any(p in {'node_modules', 'target', '.env', 'test-evidence', '.ssh'} for p in Path(name).parts):
        errors.append(f'{name}: local/generated material')
    if path.stat().st_size > 2 * 1024 * 1024:
        errors.append(f'{name}: large artifact requires separate distribution')
    data = path.read_bytes()
    for pattern in (rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{24,}', rb'(?:ghp_|github_pat_|glpat-)[A-Za-z0-9_\-]{24,}'):
        if re.search(pattern, data):
            errors.append(f'{name}: possible secret; inspect privately')
    if path.name == 'Cargo.toml':
        manifest = tomllib.loads(data.decode())
        tables = [manifest] + list(manifest.get('target', {}).values())
        for table in tables:
            for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                for dep, value in table.get(kind, {}).items():
                    actual = value.get('package', dep) if isinstance(value, dict) else dep
                    if actual in private:
                        errors.append(f'{name}: private dependency {actual}')
                    if isinstance(value, dict) and 'path' in value:
                        resolved = (path.parent / value['path']).resolve()
                        if not resolved.is_relative_to(root):
                            errors.append(f'{name}: dependency escapes repository')
                        if actual.startswith('gcoms-') and 'version' not in value and 'fuzz' not in path.parts:
                            errors.append(f'{name}: unversioned GComs dependency')
    if path.name == 'package-lock.json':
        for key, item in json.loads(data).get('packages', {}).items():
            if key.startswith('../') or (item.get('link') and not (path.parent / item['resolved']).resolve().is_relative_to(root)):
                errors.append(f'{name}: lockfile links outside repository')
    if path.name == 'package.json':
        manifest = json.loads(data)
        for kind in ('dependencies', 'devDependencies', 'optionalDependencies'):
            for dep, value in manifest.get(kind, {}).items():
                if value.startswith('file:') and not (path.parent / value[5:]).resolve().is_relative_to(root):
                    errors.append(f'{name}: npm dependency escapes repository')
# Package-local schema copy must match the browser generator input.
a = root / 'crates/rpc-contract/schemas/wire.json'
z = root / 'packages/gc-rpc/schemas/wire.json'
if a.exists() and a.read_bytes() != z.read_bytes():
    errors.append('RPC schema copies differ; regenerate both from the Rust contract')
if not paths:
    errors.append('empty source inventory')
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print(f'{len(paths)} source paths checked; no prohibited artifacts/dependencies detected')
