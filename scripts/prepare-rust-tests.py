#!/usr/bin/env python3
"""Prepare a private native-test root, including short Unix socket paths."""
import os
from pathlib import Path
import subprocess


def main():
    path = (Path(os.environ['RUNNER_TEMP']) / 'gcoms-tests' if os.name == 'nt'
            else Path('/tmp/gcoms-tests'))
    if path.is_symlink():
        raise RuntimeError('test root must not be a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == 'nt':
        sid = subprocess.check_output([
            'powershell', '-NoProfile', '-NonInteractive', '-Command',
            '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
        ], text=True).strip()
        if not sid.startswith('S-1-') or any(c not in 'S-0123456789' for c in sid):
            raise RuntimeError('invalid current-user SID')
        for args in [('/setowner', '*' + sid),
                     ('/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F')]:
            subprocess.run(['icacls', str(path), *args], check=True,
                           stdout=subprocess.DEVNULL)
    else:
        if path.stat().st_uid != os.getuid():
            raise RuntimeError('test root belongs to a different user')
        path.chmod(0o700)
    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as env:
        for name in ('TMPDIR', 'TMP', 'TEMP'):
            env.write(f'{name}={path}\n')


if __name__ == '__main__':
    main()
