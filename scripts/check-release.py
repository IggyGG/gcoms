#!/usr/bin/env python3
"""Fail closed until public identity and qualification records are supplied."""
import json, sys, subprocess
from pathlib import Path
from urllib.parse import urlparse
root = Path(__file__).resolve().parents[1]
c = json.loads((root / 'release/publication.json').read_text())
missing = []
for key in ('forgejo_url', 'companion_url'):
    u = urlparse(c.get(key) or '')
    if u.scheme != 'https' or not u.netloc or u.username or u.password or u.hostname in {'localhost', '127.0.0.1'}:
        missing.append(key)
for key in ('security_contact', 'conduct_contact'):
    value = c.get(key) or ''
    if '@' not in value or value.endswith(('.invalid', '@localhost')):
        missing.append(key)
for key in ('maintainers', 'rights_review', 'operator_acceptance'):
    if not c.get(key): missing.append(key)
for target in ('linux-x86_64', 'macos-x86_64', 'macos-aarch64', 'windows-x86_64'):
    item = c.get('native_qualification', {}).get(target, {})
    if not all(item.get(key) for key in ('source_commit', 'evidence', 'passed')):
        missing.append('native_qualification.' + target)
if c['project'] == 'gchat':
    for target in ('macos', 'windows'):
        if not c.get('publisher_identities', {}).get(target):
            missing.append('publisher_identities.' + target)
if missing:
    print('Publication blocked: ' + ', '.join(missing), file=sys.stderr)
    sys.exit(1)
subprocess.run([sys.executable, str(root / 'scripts/check-source.py')], check=True)
print('Release configuration is populated. Validate linked evidence and signatures before publishing.')
