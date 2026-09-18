#!/usr/bin/env python3
"""One-way Forgejo publication to the two IggyGG mirrors. Never force pushes."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, capture=False):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip() if capture else subprocess.run(args, cwd=ROOT, check=True)


def api(endpoint, method='GET', body=None):
    command = ['gh', 'api', '--hostname', 'github.com', '--method', method, endpoint]
    if body is None:
        return json.loads(run(command, True) or 'null')
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'body.json'; path.write_text(json.dumps(body))
        return json.loads(run(command + ['--input', str(path)], True) or 'null')


def project():
    name = json.loads((ROOT / 'release/publication.json').read_text())['project']
    if name not in ('gchat', 'gcoms'):
        raise ValueError('only GChat and GComs may be mirrored')
    return name


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--create', action='store_true')
    p.add_argument('--tag')
    p.add_argument('--dry-run', action='store_true')
    a = p.parse_args(); name = project(); repo = 'IggyGG/' + name
    if run(['git', 'status', '--porcelain'], True):
        raise ValueError('mirror requires a clean committed checkout')
    if run(['git', 'rev-parse', 'HEAD'], True) != run(['git', 'rev-parse', 'main'], True):
        raise ValueError('mirror must run on canonical main')
    refs = ['refs/heads/main:refs/heads/main']
    if a.tag:
        if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', a.tag):
            raise ValueError('only version tags may be mirrored')
        run(['git', 'verify-tag', a.tag])
        run(['git', 'merge-base', '--is-ancestor', a.tag + '^{}', 'main'])
        refs.append(f'refs/tags/{a.tag}:refs/tags/{a.tag}')
    run(['python3', 'scripts/check-source.py'])
    # Full reachable history, not just the working tree. The runner installs gitleaks.
    run(['gitleaks', 'git', '--redact', '--no-banner', '--log-opts=main', '.'])
    if a.dry_run:
        print(json.dumps({'repository': repo, 'refs': refs, 'published': False})); return
    if a.create:
        # Creation is explicit; an existing destination is examined without replacing it.
        found = subprocess.run(['gh', 'repo', 'view', repo, '--json', 'name'], capture_output=True)
        if found.returncode:
            run(['gh', 'repo', 'create', repo, '--public', '--disable-wiki', '--description',
                 f'{dict(gchat="GChat", gcoms="GComs")[name]} — public mirror; development and releases are managed in local Forgejo'])
    metadata = api('repos/' + repo)
    if metadata['full_name'].lower() != repo.lower() or metadata['private']:
        raise ValueError('destination must be the expected public mirror')
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('GIT_TRACE') and key != 'GIT_CURL_VERBOSE'}
    environment.update(GIT_TERMINAL_PROMPT='0', GIT_TRACE_REDACT='1')
    subprocess.run(['git', '-c', 'credential.helper=', '-c', 'credential.helper=!gh auth git-credential',
                    'push', '--atomic', 'https://github.com/' + repo + '.git', *refs], cwd=ROOT, env=environment, check=True)
    api('repos/' + repo + '/private-vulnerability-reporting', 'PUT')
    print('Mirrored canonical source to ' + repo)


if __name__ == '__main__':
    main()
